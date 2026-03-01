# LLMAssassin - SpamAssassin plugin for AI-powered spam detection
# Uses any OpenAI-compatible API (OpenAI, Azure, local Ollama, etc.)
#
# Copyright (C) 2026 Albus / Patronum
# Licensed under the Apache License 2.0
#
# https://github.com/patronum/LLMAssassin

package Mail::SpamAssassin::Plugin::LLMAssassin;

use strict;
use warnings;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# ── Defaults ──────────────────────────────────────────────────────────────────
use constant {
    DEF_API_BASE           => 'https://api.openai.com',
    DEF_API_KEY            => '',
    DEF_MODEL              => 'gpt-4.1',
    DEF_TIMEOUT            => 15,
    DEF_SPAM_SCORE         => 6.0,
    DEF_FAIL_SCORE         => 0.0,
    DEF_FAIL_CLOSED        => 0,       # 0 = fail open, 1 = fail closed
    DEF_MAX_BODY_CHARS     => 8000,
    DEF_MAX_CALLS_PER_MIN  => 0,       # 0 = unlimited
    DEF_DRY_RUN            => 0,       # 0 = live, 1 = log only, never score
    DEF_SKIP_AUTHENTICATED => 0,       # 1 = skip AI for SMTP-auth'd senders
    DEF_SCORE_MAP          => '',      # e.g. "0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0"
    DEF_RATE_FILE          => '/tmp/llmassassin.rate',
    DEF_SYSTEM_PROMPT      =>
        'You are an expert email spam classifier. ' .
        'Analyse the email data provided — including headers, authentication results, ' .
        'SpamAssassin signals, URLs, attachments, and body text. ' .
        'Reply with EXACTLY one JSON object and nothing else: ' .
        '{"spam": true/false, "confidence": 0.0-1.0, "reason": "<concise reason, max 8 words>"}',
};

# ── Constructor ───────────────────────────────────────────────────────────────
sub new {
    my ($class, $mailsa) = @_;
    my $self = $class->SUPER::new($mailsa);

    $self->register_eval_rule('check_llm_spam');
    $self->set_config($mailsa->{conf});

    return $self;
}

# ── Config declarations ───────────────────────────────────────────────────────
sub set_config {
    my ($self, $conf) = @_;
    my @cmds = (
        {
            setting => 'llm_api_base',
            default => DEF_API_BASE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_api_key',
            default => DEF_API_KEY,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_model',
            default => DEF_MODEL,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_timeout',
            default => DEF_TIMEOUT,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_spam_score',
            default => DEF_SPAM_SCORE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_fail_closed',
            default => DEF_FAIL_CLOSED,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_fail_score',
            default => DEF_FAIL_SCORE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            setting => 'llm_max_body_chars',
            default => DEF_MAX_BODY_CHARS,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # 0 = unlimited
            setting => 'llm_max_calls_per_minute',
            default => DEF_MAX_CALLS_PER_MIN,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # 1 = call API, log result, but never affect SA score
            setting => 'llm_dry_run',
            default => DEF_DRY_RUN,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # 1 = skip AI check for SMTP-authenticated senders
            setting => 'llm_skip_authenticated',
            default => DEF_SKIP_AUTHENTICATED,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        },
        {
            # Confidence → score map: "0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0"
            setting => 'llm_score_map',
            default => DEF_SCORE_MAP,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_system_prompt',
            default => DEF_SYSTEM_PROMPT,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
        {
            setting => 'llm_rate_file',
            default => DEF_RATE_FILE,
            type    => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        },
    );
    $conf->{parser}->register_commands(\@cmds);
}

# ── Main eval rule ────────────────────────────────────────────────────────────
sub check_llm_spam {
    my ($self, $pms) = @_;

    my $conf     = $pms->{conf};
    my $dry_run  = $conf->{llm_dry_run}            // DEF_DRY_RUN;
    my $skip_auth= $conf->{llm_skip_authenticated} // DEF_SKIP_AUTHENTICATED;

    # ── Skip authenticated senders ────────────────────────────────────────────
    if ($skip_auth && $pms->get('X-Authenticated-Sender') ne '') {
        dbg("LLMAssassin: skipping — sender is SMTP-authenticated");
        return 0;
    }

    # ── Check SA whitelist ────────────────────────────────────────────────────
    if (_is_whitelisted($pms)) {
        dbg("LLMAssassin: skipping — sender matches SA whitelist");
        return 0;
    }

    # ── Rate limiting ─────────────────────────────────────────────────────────
    my $max_calls = $conf->{llm_max_calls_per_minute} // DEF_MAX_CALLS_PER_MIN;
    if ($max_calls > 0 && !$self->_check_rate_limit($conf, $max_calls)) {
        dbg("LLMAssassin: rate limit reached ($max_calls/min)");
        my $fail_closed = $conf->{llm_fail_closed} // DEF_FAIL_CLOSED;
        if ($fail_closed) {
            my $fail_score = $conf->{llm_fail_score} // DEF_FAIL_SCORE;
            $pms->set_tag('LLMSPAMREASON', 'Rate limited');
            return $dry_run ? 0 : ($fail_score > 0 ? 1 : 0);
        }
        return 0;
    }

    # ── Build prompt content ──────────────────────────────────────────────────
    my $email_content = _build_prompt_content($pms, $conf);

    # ── Call the AI ───────────────────────────────────────────────────────────
    my ($is_spam, $confidence, $reason) = $self->_call_ai($conf, $email_content);

    if (!defined $is_spam) {
        my $fail_closed = $conf->{llm_fail_closed} // DEF_FAIL_CLOSED;
        dbg("LLMAssassin: API failed, fail_closed=$fail_closed");
        $pms->set_tag('LLMSPAMREASON', 'AI check error');
        if ($fail_closed) {
            return $dry_run ? 0 : 1;
        }
        return 0;
    }

    # ── Tag message ───────────────────────────────────────────────────────────
    my $conf_pct = int($confidence * 100);
    $pms->set_tag('LLMSPAMREASON',      $reason);
    $pms->set_tag('LLMSPAMCONFIDENCE',  $conf_pct . '%');

    dbg("LLMAssassin: spam=$is_spam confidence=$confidence reason=$reason dry_run=$dry_run");

    return 0 unless $is_spam;
    return 0 if $dry_run;

    # ── Apply score map if configured ────────────────────────────────────────
    my $score_map = $conf->{llm_score_map} // DEF_SCORE_MAP;
    if ($score_map) {
        my $mapped = _apply_score_map($score_map, $confidence);
        if (defined $mapped) {
            # Adjust the rule score dynamically
            $pms->{conf}->{scores}->{'LLM_SPAM_CHECK'} = $mapped;
            dbg("LLMAssassin: score_map applied — confidence=$confidence score=$mapped");
        }
    }

    return 1;
}

# ── Check SA whitelists ───────────────────────────────────────────────────────
sub _is_whitelisted {
    my ($pms) = @_;
    my $conf   = $pms->{conf};
    my $sender = $pms->get('From:addr');
    chomp $sender;

    for my $wl_ref (
        $conf->{whitelist_from},
        $conf->{whitelist_auth},
        $conf->{def_whitelist_from},
    ) {
        next unless ref $wl_ref eq 'HASH';
        for my $entry (keys %$wl_ref) {
            my $pattern = $entry;
            $pattern =~ s/\./\\./g;
            $pattern =~ s/\*/.*/g;
            return 1 if $sender =~ /^$pattern$/i;
        }
    }
    return 0;
}

# ── Build full prompt content ─────────────────────────────────────────────────
sub _build_prompt_content {
    my ($pms, $conf) = @_;
    my $max_chars = $conf->{llm_max_body_chars} // DEF_MAX_BODY_CHARS;
    my $content   = '';

    # ── 1. Key headers ────────────────────────────────────────────────────────
    $content .= "=== EMAIL HEADERS ===\n";
    for my $h (qw(
        From To Cc Reply-To Subject Date Message-ID
        X-Mailer User-Agent MIME-Version Content-Type
        X-Originating-IP X-Forwarded-To List-Unsubscribe Precedence
    )) {
        my $val = $pms->get($h);
        next unless defined $val && $val ne '';
        $content .= "$h: $val\n";
    }

    # ── 2. Full Received chain ────────────────────────────────────────────────
    $content .= "\n=== RECEIVED CHAIN ===\n";
    my @received = $pms->get('Received');
    $content .= join('', @received) if @received;

    # ── 3. Authentication results ─────────────────────────────────────────────
    $content .= "\n=== AUTHENTICATION ===\n";
    for my $h (qw(
        Authentication-Results
        DKIM-Signature
        Received-SPF
        X-Google-DKIM-Signature
        ARC-Authentication-Results
    )) {
        my $val = $pms->get($h);
        next unless defined $val && $val ne '';
        $content .= "$h: $val\n";
    }

    # ── 4. SpamAssassin signals ───────────────────────────────────────────────
    $content .= "\n=== SPAMASSASSIN SIGNALS ===\n";
    my $sa_score = $pms->{score} // 0;
    $content .= "Current SA score: $sa_score\n";

    my $bayes = $pms->get_tag('BAYESSCORE');
    $content .= "Bayes probability: $bayes\n" if defined $bayes && $bayes ne '';

    # Rules that have fired so far
    my @fired = grep { $pms->get_score($_) != 0 } keys %{ $pms->{test_log_msgs} // {} };
    if (@fired) {
        $content .= "Rules fired: " . join(', ', sort @fired) . "\n";
    }

    # ── 5. URLs extracted from body ───────────────────────────────────────────
    $content .= "\n=== URLS FOUND IN EMAIL ===\n";
    my @uris = $pms->get_uri_list();
    if (@uris) {
        $content .= join("\n", @uris) . "\n";
    } else {
        $content .= "None\n";
    }

    # ── 6. Attachment signals ─────────────────────────────────────────────────
    $content .= "\n=== ATTACHMENTS ===\n";
    my $msg        = $pms->{msg};
    my @all_parts  = $msg->find_parts(qr/./, 1);
    my @attachments;
    for my $part (@all_parts) {
        my $ct   = $part->get_header('content-type')        // '';
        my $cd   = $part->get_header('content-disposition') // '';
        if ($cd =~ /attachment/i || $ct =~ /application|image|audio|video/i) {
            my ($filename) = $cd =~ /filename="?([^";]+)"?/i;
            $filename //= 'unnamed';
            $ct =~ s/\s+/ /g;
            push @attachments, "  - $filename ($ct)";
        }
    }
    $content .= @attachments ? join("\n", @attachments) . "\n" : "None\n";

    # ── 7. Plain text body ────────────────────────────────────────────────────
    $content .= "\n=== BODY ===\n";
    my $body  = '';
    my @parts = $msg->find_parts(qr/text\/plain/i);
    @parts    = $msg->find_parts(qr/./) unless @parts;
    for my $part (@parts) {
        my $decoded = $part->decode();
        next unless defined $decoded;
        $body .= $decoded;
        last if length($body) > $max_chars * 2;
    }
    $body     = substr($body, 0, $max_chars) if length($body) > $max_chars;
    $content .= $body . "\n";

    return $content;
}

# ── Apply confidence → score map ──────────────────────────────────────────────
sub _apply_score_map {
    my ($map_str, $confidence) = @_;

    # Format: "0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0"
    for my $entry (split /,/, $map_str) {
        $entry = _trim($entry);
        if ($entry =~ /^([\d.]+)-([\d.]+)=([\d.]+)$/) {
            my ($low, $high, $score) = ($1+0, $2+0, $3+0);
            if ($confidence >= $low && $confidence <= $high) {
                return $score;
            }
        }
    }
    return undef;
}

# ── Rate limiter ──────────────────────────────────────────────────────────────
sub _check_rate_limit {
    my ($self, $conf, $max_calls) = @_;
    my $rate_file = $conf->{llm_rate_file} // DEF_RATE_FILE;
    my $now       = time();
    my $window    = 60;

    # Read existing timestamps
    my @timestamps;
    if (open my $fh, '<', $rate_file) {
        @timestamps = map { chomp; $_ + 0 } <$fh>;
        close $fh;
    }

    # Keep only timestamps within the last 60 seconds
    @timestamps = grep { $now - $_ < $window } @timestamps;

    if (scalar(@timestamps) >= $max_calls) {
        return 0;  # rate limit hit
    }

    # Record this call
    push @timestamps, $now;
    if (open my $fh, '>', $rate_file) {
        print $fh "$_\n" for @timestamps;
        close $fh;
    }

    return 1;  # allowed
}

# ── Call OpenAI-compatible API ────────────────────────────────────────────────
sub _call_ai {
    my ($self, $conf, $content) = @_;

    my $api_base      = $conf->{llm_api_base}     // DEF_API_BASE;
    my $api_key       = $conf->{llm_api_key}       // DEF_API_KEY;
    my $model         = $conf->{llm_model}         // DEF_MODEL;
    my $timeout       = $conf->{llm_timeout}       // DEF_TIMEOUT;
    my $system_prompt = $conf->{llm_system_prompt} // DEF_SYSTEM_PROMPT;

    $api_base =~ s|/+$||;
    my $url = "$api_base/v1/chat/completions";

    my $payload = _json_encode({
        model       => $model,
        temperature => 0,
        max_tokens  => 100,
        messages    => [
            { role => 'system', content => $system_prompt },
            { role => 'user',   content => $content       },
        ],
    });

    my @cmd = (
        'curl', '-s', '-S',
        '--max-time', $timeout,
        '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-H', 'Accept: application/json',
    );

    if ($api_key) {
        push @cmd, '-H', "Authorization: Bearer $api_key";
    }

    push @cmd, '--data-binary', $payload, $url;

    my $response = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout + 2);
        $response = `@cmd 2>/dev/null`;
        alarm(0);
    };

    if ($@ || !$response) {
        dbg("LLMAssassin: curl error or timeout: " . ($@ // 'empty response'));
        return (undef, undef, undef);
    }

    # Extract content field from JSON response
    my ($http_content) = $response =~ /"content"\s*:\s*"(.*?)"\s*[,}]/s;
    unless ($http_content) {
        dbg("LLMAssassin: could not extract content from response: $response");
        return (undef, undef, undef);
    }

    # Unescape JSON string
    $http_content =~ s/\\n/\n/g;
    $http_content =~ s/\\"/"/g;
    $http_content =~ s/\\\\/\\/g;
    $http_content =~ s/^```(?:json)?\s*//i;
    $http_content =~ s/\s*```$//;
    $http_content = _trim($http_content);

    my ($spam_val)  = $http_content =~ /"spam"\s*:\s*(true|false)/i;
    my ($conf_val)  = $http_content =~ /"confidence"\s*:\s*([\d.]+)/i;
    my ($reason)    = $http_content =~ /"reason"\s*:\s*"([^"]+)"/i;

    unless (defined $spam_val) {
        dbg("LLMAssassin: could not parse response JSON: $http_content");
        return (undef, undef, undef);
    }

    my $is_spam    = (lc($spam_val) eq 'true') ? 1 : 0;
    my $confidence = defined $conf_val ? $conf_val + 0 : ($is_spam ? 1.0 : 0.0);
    $reason      //= 'No reason provided';

    return ($is_spam, $confidence, $reason);
}

# ── Minimal JSON encoder (no CPAN dependency) ─────────────────────────────────
sub _json_encode {
    my ($data) = @_;
    if (ref $data eq 'HASH') {
        my @pairs;
        for my $k (sort keys %$data) {
            push @pairs, _json_str($k) . ':' . _json_encode($data->{$k});
        }
        return '{' . join(',', @pairs) . '}';
    }
    if (ref $data eq 'ARRAY') {
        return '[' . join(',', map { _json_encode($_) } @$data) . ']';
    }
    if (!defined $data)                                { return 'null' }
    if ($data =~ /^-?\d+(\.\d+)?$/ && !ref $data)    { return $data  }
    return _json_str($data);
}

sub _json_str {
    my ($s) = @_;
    $s =~ s/\\/\\\\/g;
    $s =~ s/"/\\"/g;
    $s =~ s/\n/\\n/g;
    $s =~ s/\r/\\r/g;
    $s =~ s/\t/\\t/g;
    return '"' . $s . '"';
}

sub _trim { my $s = shift; $s =~ s/^\s+|\s+$//g; $s }

1;

__END__

=head1 NAME

Mail::SpamAssassin::Plugin::LLMAssassin - AI-powered spam detection via OpenAI-compatible APIs

=head1 SYNOPSIS

In C</etc/spamassassin/llmassassin.pre>:

  loadplugin Mail::SpamAssassin::Plugin::LLMAssassin /etc/spamassassin/LLMAssassin.pm

In C</etc/spamassassin/llmassassin.cf>:

  llm_api_base              https://api.openai.com
  llm_api_key               sk-your-key-here
  llm_model                 gpt-4.1
  llm_spam_score            6.0
  llm_fail_closed           0
  llm_dry_run               0
  llm_skip_authenticated    1
  llm_max_calls_per_minute  0
  llm_score_map             0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0

  header   LLM_SPAM_CHECK  eval:check_llm_spam()
  describe LLM_SPAM_CHECK  LLM classified this email as spam
  score    LLM_SPAM_CHECK  6.0

  # Show reason in mail headers
  add_header all LLM-Spam-Reason   _LLMSPAMREASON_
  add_header all LLM-Confidence    _LLMSPAMCONFIDENCE_

=head1 DESCRIPTION

LLMAssassin is a SpamAssassin plugin that classifies email using any
OpenAI-compatible LLM API. It passes the LLM a rich context including:

=over 4

=item * Email headers and full Received chain

=item * DKIM, SPF, DMARC and ARC authentication results

=item * SpamAssassin's own score, Bayes probability, and fired rules

=item * All URLs extracted from the body

=item * Attachment filenames and MIME types

=item * Plain text body (truncated to llm_max_body_chars)

=back

The AI returns a spam verdict, confidence score (0.0-1.0), and a short reason.
Confidence maps to SA scores via C<llm_score_map> for fine-grained control.

=head1 CONFIGURATION

=over 4

=item B<llm_api_base> (default: https://api.openai.com)

Base URL of the OpenAI-compatible API. No trailing slash.

=item B<llm_api_key> (default: empty)

Bearer token. Sent as C<Authorization: Bearer <key>>.

=item B<llm_model> (default: gpt-4.1)

Model name passed to the API.

=item B<llm_timeout> (default: 15)

Seconds before the API call times out.

=item B<llm_spam_score> (default: 6.0)

Flat score added when AI says spam. Overridden per-message by llm_score_map if set.

=item B<llm_score_map> (default: empty)

Map confidence ranges to SA scores. Format: C<low-high=score,...>

Example: C<0.9-1.0=8.0,0.7-0.9=5.0,0.5-0.7=2.0>

=item B<llm_fail_closed> (default: 0)

C<0> = fail open (score 0 on error). C<1> = fail closed (apply llm_fail_score).

=item B<llm_fail_score> (default: 0.0)

Score applied on failure when llm_fail_closed is 1.

=item B<llm_dry_run> (default: 0)

C<1> = call API and log but never affect SA score. Use for tuning before go-live.

=item B<llm_skip_authenticated> (default: 0)

C<1> = skip AI check for SMTP-authenticated senders (your own users).

=item B<llm_max_calls_per_minute> (default: 0)

Rate limit on API calls per minute across all users. C<0> = unlimited.

=item B<llm_max_body_chars> (default: 8000)

Max body characters sent to AI. Caps token usage.

=item B<llm_system_prompt> (default: built-in)

Override the system prompt. Must instruct the model to return:
C<{"spam": true/false, "confidence": 0.0-1.0, "reason": "..."}>

=item B<llm_rate_file> (default: /tmp/llmassassin.rate)

Path to the rate limiter state file.

=back

=head1 SA TAGS

The plugin exposes two tags usable in C<add_header> directives:

  _LLMSPAMREASON_      — Short reason from the AI
  _LLMSPAMCONFIDENCE_  — Confidence percentage (e.g. "94%")

=head1 AUTHOR

Albus / Patronum

=head1 LICENSE

Apache License 2.0

=cut
