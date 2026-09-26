<?php
declare(strict_types=1);

session_start();

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '../../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(dirname(__DIR__));
$dotenv->safeLoad();

$smtp_host      = $_ENV['SMTP_HOST'];
$smtp_port      = (int)$_ENV['SMTP_PORT'];
$smtp_user      = $_ENV['SMTP_USER'];
$smtp_pass      = $_ENV['SMTP_PASS'];
$smtp_secure    = PHPMailer::ENCRYPTION_STARTTLS;

$admin_email    = $_ENV['ADMIN_EMAIL'];
$from_email     = $_ENV['FROM_EMAIL'];
$from_name      = $_ENV['FROM_NAME'];
$subject_prefix = '[Contact Form] ';

$turnstileSecret = $_ENV['TURNSTILE_SECRET'];

$errors  = [];
$success = false;
$old     = [
  'name'                  => '',
  'email'                 => '',
  'reason'                => '',
  'title'                 => '',
  'details'               => '',
  'spam_email_sender'     => '',
  'spam_original_message' => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $_SESSION['contact_form_loaded_at'] = time();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // ---- Honeypot ----
  if (!empty($_POST['website'])) {
    $success = true;
  }

  // ---- Submission timing check ----
  $formLoadedAt = $_SESSION['contact_form_loaded_at'] ?? null;
  unset($_SESSION['contact_form_loaded_at']);

  if ($formLoadedAt === null) {
    $errors[] = 'Invalid form session. Please reload the page.';
  } else {
    $submissionTime = time() - $formLoadedAt;

    if ($submissionTime < 5) {
      $errors[] = 'Form submitted too quickly. Please try again.';
    }
  }
  // ---- Collect & sanitize ----
  $old['name']                  = trim((string)($_POST['name'] ?? ''));
  $old['email']                 = trim((string)($_POST['email'] ?? ''));
  $old['reason']                = trim((string)($_POST['reason'] ?? ''));
  $old['title']                 = trim((string)($_POST['title'] ?? ''));
  $old['details']               = trim((string)($_POST['details'] ?? ''));
  $old['spam_email_sender']     = trim((string)($_POST['spam_email_sender'] ?? ''));
  $old['spam_original_message'] = trim((string)($_POST['spam_original_message'] ?? ''));
  $confirmation                 = isset($_POST['confirmation']);
  $turnstileToken               = (string)($_POST['cf-turnstile-response'] ?? '');

  // ---- Validation ----
  if ($old['name'] === '' || mb_strlen($old['name']) < 2 || mb_strlen($old['name']) > 24) {
    $errors[] = 'Name is required (2–24 characters).';
  }
  if ($old['email'] === '' || !filter_var($old['email'], FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'A valid email address is required.';
  }
  $allowed_reasons = ['spam_report', 'service_issue'];
  if ($old['reason'] === '') {
    $errors[] = 'Please select a reason.';
  } elseif (!in_array($old['reason'], $allowed_reasons, true)) {
    $errors[] = 'Invalid reason selected.';
  }
  if ($old['title'] === '' || mb_strlen($old['title']) < 6 || mb_strlen($old['title']) > 50) {
    $errors[] = 'Title is required (6–50 characters).';
  }
  if ($old['details'] === '') {
    $errors[] = 'Details are required.';
  }
  if (!$confirmation) {
    $errors[] = 'You must confirm that the information is accurate.';
  }

  // ---- Conditional spam fields ----
  $is_spam = $old['reason'] === 'spam_report';
  if ($is_spam) {
    if ($old['spam_email_sender'] === '' || !filter_var($old['spam_email_sender'], FILTER_VALIDATE_EMAIL)) {
      $errors[] = 'Spam Email Sender is required and must be a valid email when reporting spam.';
    }
    if ($old['spam_original_message'] === '') {
      $errors[] = 'Original Message is required when reporting spam.';
    }
  }

  // ---- Turnstile Check ----
  if ($turnstileToken === '') {
    $errors[] = 'Please complete the security verification.';
  } else {
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');

    curl_setopt_array($ch, [
      CURLOPT_POST           => true,
      CURLOPT_POSTFIELDS     => http_build_query([
        'secret'   => $turnstileSecret,
        'response' => $turnstileToken,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
      ]),
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => 10,
    ]);

    $turnstileResponse = curl_exec($ch);

    if ($turnstileResponse === false) {
      $errors[] = 'Unable to verify the security challenge. Please try again.';
    } else {
      $turnstileResult = json_decode($turnstileResponse, true);

      if (
        !is_array($turnstileResult) ||
        ($turnstileResult['success'] ?? false) !== true
      ) {
        $errors[] = 'Security verification failed. Please try again.';
      }
    }
    curl_close($ch);
  }

  // ---- Send emails if valid ----
  if (empty($errors)) {
    $reason_labels = [
      'spam_report'   => 'Spam Report',
      'service_issue' => 'Service Issue',
    ];
    $reasons_text = $reason_labels[$old['reason']] ?? $old['reason'];

    $body  = "New contact form submission\n";
    $body .= "===========================\n\n";
    $body .= "Name:    {$old['name']}\n";
    $body .= "Email:   {$old['email']}\n";
    $body .= "Reason:  {$reasons_text}\n";
    $body .= "Title:   {$old['title']}\n\n";
    $body .= "Details:\n{$old['details']}\n\n";

    if ($is_spam) {
      $body .= "--- Spam Report Details ---\n";
      $body .= "Spam Email Sender: {$old['spam_email_sender']}\n\n";
      $body .= "Original Message:\n{$old['spam_original_message']}\n";
    }

    $body .= "\n--\nSubmitted: " . date('Y-m-d H:i:s T') . "\n";
    $body .= "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";

    $subject = $subject_prefix . $old['title'];

    try {
      // ---- 1) Email to admin ----
      $mail = new PHPMailer(true);

      $mail->isSMTP();
      $mail->Host       = $smtp_host;
      $mail->SMTPAuth   = true;
      $mail->Username   = $smtp_user;
      $mail->Password   = $smtp_pass;
      $mail->SMTPSecure = $smtp_secure;
      $mail->Port       = $smtp_port;
      $mail->CharSet    = 'UTF-8';

      $mail->setFrom($from_email, $from_name);
      $mail->addAddress($admin_email);
      $mail->addReplyTo($old['email'], $old['name']);

      $mail->Subject = $subject;
      $mail->Body    = $body;

      $mail->send();

      // ---- 2) Confirmation to submitter ----
      $mail->clearAddresses();
      $mail->clearReplyTos();

      $mail->addAddress($old['email'], $old['name']);
      $mail->Subject = 'We received your message: ' . $old['title'];

      $confirm_body  = "Hello {$old['name']},\n\n";
      $confirm_body .= "Thank you for contacting us. We have received your message and will get back to you if needed.\n\n";
      $confirm_body .= "Summary of what you submitted:\n";
      $confirm_body .= "------------------------------\n";
      $confirm_body .= "Reason: {$reasons_text}\n";
      $confirm_body .= "Title:  {$old['title']}\n\n";
      $confirm_body .= "Details:\n{$old['details']}\n\n";
      if ($is_spam) {
        $confirm_body .= "Spam Email Sender: {$old['spam_email_sender']}\n";
      }
      $confirm_body .= "\n--\nThis is an automated confirmation.\n";

      $mail->Body = $confirm_body;
      $mail->send();

      $success = true;
      $old = [
        'name' => '', 'email' => '', 'reason' => '', 'title' => '',
        'details' => '', 'spam_email_sender' => '', 'spam_original_message' => '',
      ];

    } catch (Exception $e) {
      $errors[] = 'Sorry, there was a problem sending the email. Please try again later.';
    }
  }
  else {
    $_SESSION['contact_form_loaded_at'] = time();
  }
}

// Helper for sticky checkboxes
function checked(string $value, array $selected): string {
    return in_array($value, $selected, true) ? ' checked' : '';
}
?>
<!-- Imma be real I did not handwrite this -->
<!doctype html>
<html lang="en-US">
  <head>
    <title>Contact - DES</title>
    <meta charset="utf-8" />
    <link rel="stylesheet" href="/index.css">
    <link rel="icon" type="image/x-icon" href="/favicon.ico" />
    <style>
      .error-box   { background:#fee; border:1px solid #c00; color:#900; padding:12px; margin-bottom:1.5rem; border-radius:4px; }
      .success-box { background:#efe; border:1px solid #090; color:#060; padding:12px; margin-bottom:1.5rem; border-radius:4px; }
      .error-box ul { margin:0.5rem 0 0 1.2rem; }
      .spam-fields { display:none; }
      .spam-fields.visible { display:block; }
    </style>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <script defer src="https://analytics.andrewstill.cloud/script.js" data-website-id="19db9fd2-efcf-4ccd-9de0-642b582b7aa9"></script>
  </head>
  <body>
    <header>
      <h1>Contact</h1>
      <nav style="display: flex;align-items: center;gap: 3px;">
        <a href="/index.html">
          <div style="padding: 4px 12px;">Home</div>
        </a>
        <a href="/status.html">
          <div style="padding: 4px 12px;">Status</div>
        </a>
        <a href="/blacklist.html">
          <div style="padding: 4px 12px;">Blocklist Check</div>
        </a>
        <a href="/config.html">
          <div style="padding: 4px 12px;">Configuration</div>
        </a>
        <a href="/about.html">
          <div style="padding: 4px 12px;">About</div>
        </a>
        <a href="/contact.php">
          <div style="padding: 4px 12px;">Contact</div>
        </a>
      </nav>
    </header>
    <main>
      <?php if ($success): ?>
      <div class="success-box">
        <strong>Thank you!</strong> Your message has been sent successfully.
        A confirmation has also been emailed to you.
      </div>
      <?php endif; ?>

      <?php if (!empty($errors)): ?>
        <div class="error-box">
          <strong>Please fix the following:</strong>
          <ul>
            <?php foreach ($errors as $e): ?>
              <li><?= htmlspecialchars($e, ENT_QUOTES, 'UTF-8') ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>
      <form action="" method="POST" id="contact-form" novalidate>
        <div style="display:flex;gap: 12px">
          <div style="margin-bottom: 1rem;">
            <label for="name">Name</label><br>
            <input type="text" id="name" name="name" required minlength="2" maxlength="24" value="<?= htmlspecialchars($old['name'], ENT_QUOTES, 'UTF-8') ?>">
          </div>
          <div style="margin-bottom: 1rem;">
            <label for="email">Email</label><br>
            <input type="email" id="email" name="email" required value="<?= htmlspecialchars($old['email'], ENT_QUOTES, 'UTF-8') ?>">
          </div>
          <div style="position:absolute;left:-9999px;" aria-hidden="true">
            <label for="website">Website</label>
            <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
          </div>
        </div>
        

        <div style="margin-bottom: 1rem;">
          <label>Reason <span style="color:#c00">*</span></label><br>
          <label><input type="radio" name="reason" value="spam_report" id="reason_spam"
            <?= ($old['reason'] === 'spam_report') ? 'checked' : '' ?>> Spam Report</label><br>
          <label><input type="radio" name="reason" value="service_issue"
            <?= ($old['reason'] === 'service_issue') ? 'checked' : '' ?>> Service Issue</label>
        </div>

        <div style="margin-bottom: 1rem;">
          <label for="title">Title</label><br>
          <input style="width:380px;" type="text" id="title" name="title" minlength="6" maxlength="50" required value="<?= htmlspecialchars($old['title'], ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <div style="margin-bottom: 1rem;">
          <label for="details">Details</label><br>
          <textarea id="details" name="details" required rows="6"><?= htmlspecialchars($old['details'], ENT_QUOTES, 'UTF-8') ?></textarea>
        </div>

        <!-- Spam fields (shown/required only when "Spam Report" is checked) -->
        <div class="spam-fields<?= (($old['reason'] ?? '') === 'spam_report') ? ' visible' : '' ?>" id="spam-fields">
          <div style="margin-bottom: 1rem;">
            <label for="spam_email_sender">Spam – Email Sender</label><br>
            <input type="email" id="spam_email_sender" name="spam_email_sender" placeholder="fake@dragonaere.com" value="<?= htmlspecialchars($old['spam_email_sender'], ENT_QUOTES, 'UTF-8') ?>">
          </div>
          <div style="margin-bottom: 1rem;">
            <label for="spam_original_message">Spam – Original Message</label><br>
            <textarea id="spam_original_message" name="spam_original_message" rows="8" placeholder="See below for info on how to find"><?= htmlspecialchars($old['spam_original_message'], ENT_QUOTES, 'UTF-8') ?></textarea>
            <p>To get the original message, follow this <a href="https://support.google.com/mail/answer/29436">Google Support Article</a> that includes instructions for Gmail and other major mail clients.</p>
          </div>
        </div>

        <div style="margin-bottom: 1.5rem;">
          <label>
            <input type="checkbox" name="confirmation" value="1" required
              <?= isset($_POST['confirmation']) ? ' checked' : '' ?>>
            I confirm that the information provided is accurate.
          </label>
        </div>

        <div class="cf-turnstile" data-sitekey="0x4AAAAAAEOCiJhxLfND2bT5" data-action="contact"></div>

        <button type="submit">Submit</button>
      </form>
    </main>
    <footer style="width: 100%;position: absolute;bottom: 0;display: flex;gap: 20px">
      <p>© 2026 Dragonaere Enterprises</p>
      <p style="font-weight: bold;"> — </p>
      <p style="font-style: italic;">Powered by <a
          href="https://www.proxmox.com/en/products/proxmox-mail-gateway/overview">Proxmox Mail Gateway</a> and <a
          href="https://maddy.email">Maddy</a>.</p>
    </footer>
    <script>
      (function () {
        const reasonRadios = document.querySelectorAll('input[name="reason"]');
        const spamRadio    = document.getElementById('reason_spam');
        const spamFields   = document.getElementById('spam-fields');
        const senderInput  = document.getElementById('spam_email_sender');
        const messageInput = document.getElementById('spam_original_message');

        function toggleSpamFields() {
          const show = spamRadio.checked;

          spamFields.classList.toggle('visible', show);
          senderInput.required  = show;
          messageInput.required = show;

          if (!show) {
            senderInput.value  = '';
            messageInput.value = '';
          }
        }

        reasonRadios.forEach(radio => {
          radio.addEventListener('change', toggleSpamFields);
        });

        toggleSpamFields();
      })();
    </script>
  </body>
</html>