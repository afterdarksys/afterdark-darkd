#!/bin/bash
# Send welcome emails to all users with SSO login instructions

set -e

echo "📧 Sending Welcome Emails to After Dark SSO Users..."
echo ""

# User information
declare -A USERS=(
  ["rams3377"]="rams3377@gmail.com|Ram"
  ["tommym2006"]="tommym2006@gmail.com|Tommy"
  ["rjc"]="rjc@afterdarksys.com|RJC"
  ["alikassim1996"]="alikassim1997@gmail.com|Ali Kassim"
)

# Email template
create_email_template() {
  local name=$1
  local username=$2
  local email=$3

  cat <<EOF
Subject: Welcome to After Dark Authentication (SSO) 🔐

Hi $name,

Your After Dark single sign-on (SSO) account has been activated!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎉 WHAT THIS MEANS FOR YOU:

You now have ONE account that works across ALL After Dark services:

✅ 30 Main Services (viralvisions.io, aeims.app, cats.center, etc.)
✅ 17 Internal Tools (admin, api, billing, analytics, etc.)
✅ Security Platform (dnsscience.io)

Total: 48 services, ONE login!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔐 YOUR LOGIN DETAILS:

Auth Portal: https://auth.afterdarksys.com
Username: $username
Email: $email

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚀 HOW TO LOGIN:

1. Visit ANY After Dark service (e.g., https://viralvisions.io)
2. Click "Sign in with SSO" button
3. You'll be redirected to auth.afterdarksys.com
4. Enter your username and password
5. Boom! You're logged in across ALL services!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔑 FIRST TIME SETUP:

If you need to set/reset your password:

1. Go to: https://auth.afterdarksys.com/if/flow/default-recovery-flow/
2. Enter your email: $email
3. Check your inbox for password reset link
4. Set a strong password
5. Done! Now you can login to all services

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 AVAILABLE SERVICES:

Main Services:
• viralvisions.io - Marketing Analytics
• aeims.app - AI Enterprise Management
• cats.center - Pet Platform (with TechCat!)
• dogs.institute - Dog Training
• aiserve.farm - AI Infrastructure
• And 25 more...

Internal Tools:
• admin.afterdarksys.com - Admin Portal
• api.afterdarksys.com - API Gateway
• billing.afterdarksys.com - Billing
• analytics.afterdarksys.com - Analytics
• And 13 more...

Security:
• dnsscience.io - DNS Analytics & Threat Intel

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 PRO TIPS:

1. Single Sign-On (SSO):
   Login once → Access all services automatically!

2. Password Best Practices:
   Use a strong, unique password for your SSO account

3. Need Help?
   Contact: support@afterdarksys.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 QUICK TEST:

1. Visit: https://viralvisions.io/login
2. Click: "Sign in with SSO"
3. Login with your credentials
4. Visit: https://cats.center
5. You're already logged in! (SSO magic ✨)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Welcome to the After Dark ecosystem!

Best regards,
After Dark Systems Team

🔐 Powered by After Dark Authentication
🐈 CAT POWURRRRRR
EOF
}

# Function to send email (requires mail command or SMTP)
send_email() {
  local email=$1
  local name=$2
  local username=$3
  local template_file="/tmp/welcome_${username}.txt"

  create_email_template "$name" "$username" "$email" > "$template_file"

  echo "📧 $name ($email)"
  echo "   Template created: $template_file"
  echo "   ⚠️  Manual action required: Send this email"
  echo ""
}

# Generate emails for all users
for username in "${!USERS[@]}"; do
  IFS='|' read -r email name <<< "${USERS[$username]}"
  send_email "$email" "$name" "$username"
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Email templates generated!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📧 Templates saved to /tmp/welcome_*.txt"
echo ""
echo "🚀 NEXT STEPS:"
echo ""
echo "Option 1: Manual Email (Recommended for now)"
echo "  - Open each template file"
echo "  - Copy contents"
echo "  - Send via your email client"
echo ""
echo "Option 2: Automated Email (Requires SMTP setup)"
echo "  - Configure Authentik email settings"
echo "  - Use Authentik's built-in email notifications"
echo ""
echo "Option 3: CLI Email (If mail command available)"
echo "  for f in /tmp/welcome_*.txt; do"
echo "    email=\$(grep 'Email:' \$f | awk '{print \$2}')"
echo "    mail -s 'Welcome to After Dark SSO' \$email < \$f"
echo "  done"
echo ""
echo "📝 Users to notify:"
echo "  • Ram (rams3377@gmail.com)"
echo "  • Tommy (tommym2006@gmail.com)"
echo "  • RJC (rjc@afterdarksys.com)"
echo "  • Ali Kassim (alikassim1997@gmail.com)"
