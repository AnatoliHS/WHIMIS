export async function onRequestPost(context) {
  try {
    const formData = await context.request.formData();
    const data = Object.fromEntries(formData.entries());

    // 1. Honeypot Check
    // If a bot fills out the hidden 'website' field, silently succeed without sending the email
    if (data.website) {
      return Response.redirect('https://whmiswise.com/thanks', 303);
    }

    // 1.2 Turnstile Verification
    const turnstileToken = data['cf-turnstile-response'];
    const ip = context.request.headers.get('CF-Connecting-IP');

    if (!turnstileToken) {
      return new Response(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px; color: #333;">
          <h2>Security Check Failed</h2>
          <p>Please complete the Turnstile verification.</p>
          <button onclick="window.history.back()" style="padding: 10px 20px; cursor: pointer; background: #0968e5; color: white; border: none; border-radius: 5px;">Go Back</button>
        </div>
      `, { status: 400, headers: { 'Content-Type': 'text/html' } });
    }

    let verificationBody = new FormData();
    verificationBody.append('secret', context.env.TURNSTILE_SECRET_KEY);
    verificationBody.append('response', turnstileToken);
    verificationBody.append('remoteip', ip);

    const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      body: verificationBody,
      method: 'POST',
    });

    const outcome = await verificationResult.json();
    if (!outcome.success) {
      return new Response(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px; color: #333;">
          <h2>Security Check Failed</h2>
          <p>Turnstile verification failed. Spam detected.</p>
          <button onclick="window.history.back()" style="padding: 10px 20px; cursor: pointer; background: #0968e5; color: white; border: none; border-radius: 5px;">Go Back</button>
        </div>
      `, { status: 403, headers: { 'Content-Type': 'text/html' } });
    }

    // 2. Validate basic fields
    if (!data.name || !data.email || !data.message) {
      return new Response('Missing required fields.', { status: 400 });
    }

    // 2.5 Validate Email Domain (DNS MX Record Check)
    const emailStr = data.email || '';
    // Basic regex check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailStr)) {
      return new Response('Invalid email format.', { status: 400 });
    }

    const domainMatch = emailStr.match(/@(.+)$/);
    if (!domainMatch) {
      return new Response('Invalid email domain format.', { status: 400 });
    }
    const domain = domainMatch[1];

    const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`, {
      headers: { 'Accept': 'application/dns-json' }
    });

    if (dnsResponse.ok) {
      const dnsData = await dnsResponse.json();
      if (dnsData.Status !== 0 || !dnsData.Answer || dnsData.Answer.length === 0) {
        return new Response(`
          <div style="font-family: sans-serif; text-align: center; margin-top: 50px; color: #333;">
            <h2>Email Validation Failed</h2>
            <p>The email domain "<b>@${domain}</b>" does not appear to exist or cannot receive emails.</p>
            <button onclick="window.history.back()" style="padding: 10px 20px; cursor: pointer; background: #0968e5; color: white; border: none; border-radius: 5px;">Go Back</button>
          </div>
        `, { status: 400, headers: { 'Content-Type': 'text/html' } });
      }
    }

    // 3. Build the email body
    const emailBody = `
      <h2>New Inquiry from WHMIS Wise Website</h2>
      <p><strong>Name:</strong> ${data.name}</p>
      <p><strong>Email:</strong> ${data.email}</p>
      <p><strong>Message:</strong></p>
      <p>${data.message}</p>
    `;

    // 4. Send email using Resend
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${context.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'onboarding@resend.dev', // Resend default address for unverified domains
        to: ['tony_777@hotmail.com'], // The email where you want to receive these messages
        reply_to: data.email,
        subject: data._subject || `New Inquiry from ${data.name}`,
        html: emailBody,
      }),
    });

    // 5. If successful, redirect the user to your custom thanks page
    if (response.ok) {
      return Response.redirect('https://whmiswise.com/thanks', 303);
    } else {
      // If Resend throws an error, catch it
      const errorText = await response.text();
      console.error("Resend Error:", errorText);
      return new Response('Error sending email. Please try again later.', { status: 500 });
    }
  } catch (err) {
    console.error("Server Error:", err.message);
    return new Response('Server Error: ' + err.message, { status: 500 });
  }
}
