"""Synthetic social-engineering corpus (offline demo). Swap ml/data/messages.csv (text,label) for
SMS Spam Collection / Enron-phishing / your own labelled data for production."""
import csv, pathlib, random
R = random.Random(7)
OUT = pathlib.Path(__file__).parent / "data" / "messages.csv"
LINK = ["http://bit.ly/3xKd9", "https://secure-verify-login.xyz/a", "http://{b}-update.top/login", "www.claim-reward.info/now", "https://tinyurl.com/y8k2m"]
AMT = ["Rs 5,000", "$250", "Rs 25,00,000", "$1,000,000", "Rs 49,999"]
BANK = ["HDFC", "SBI", "ICICI", "Axis Bank", "Chase", "Wells Fargo", "PayPal", "your bank"]
URG = ["immediately", "within 24 hours", "today", "urgently", "right now", "before midnight"]
T = {
 "banking_scam": ["Dear customer, your {b} account will be blocked {u}. Verify your KYC using this link {l}",
   "ALERT: Unusual login detected on your {b} account. Confirm your details {u} at {l} or access will be suspended",
   "{b}: your debit card has been deactivated. Update your PAN and card number now {l}",
   "Your account has been limited due to suspicious activity. Log in {u} to restore access {l}"],
 "delivery_scam": ["Your parcel could not be delivered. Pay a redelivery fee of Rs 29 here {l}",
   "DHL: package on hold due to incomplete address. Update address {u} {l}",
   "FedEx: we attempted delivery but failed. Reschedule and pay customs charges {l}",
   "India Post: your shipment is held at the warehouse. Confirm address to avoid return {l}"],
 "lottery_scam": ["Congratulations! You have won {a} in the lucky draw. Claim your prize {u} {l}",
   "You are the lucky winner of our mega lottery. Send your bank details to receive {a}",
   "WINNER! Your mobile number was selected for a free gift worth {a}. Click {l} to claim",
   "Dear winner, to release your {a} prize pay the processing fee today"],
 "job_scam": ["Work from home and earn {a} per day. No experience needed. Message us on WhatsApp now {l}",
   "We reviewed your resume. You are selected for a part-time job, earn {a} daily just by liking videos",
   "Urgent hiring! Registration fee required to confirm your job offer. Pay {u} {l}",
   "Congratulations, your profile is shortlisted. Send your Aadhaar and bank details to join {u}"],
 "investment_scam": ["Double your money in 7 days! Guaranteed returns on crypto trading. Join {l}",
   "Exclusive VIP signal group: earn {a} weekly with zero risk. Limited slots {u} {l}",
   "Invest {a} today and receive 300% profit. Our expert trader guarantees returns",
   "Bitcoin giveaway: send 0.1 BTC and get 0.2 BTC back instantly {l}"],
 "government_scam": ["Income Tax Department: you are eligible for a refund of {a}. Submit bank details {l}",
   "Your Aadhaar will be deactivated {u}. Link your mobile at {l} to avoid legal action",
   "Traffic police notice: unpaid challan {a}. Pay now to avoid arrest warrant {l}",
   "IRS final notice: legal action will be taken unless you pay the outstanding tax {u}"],
 "otp_scam": ["Do not ignore. Share the OTP you just received to cancel the unauthorised transaction of {a}",
   "This is {b} customer care. Please tell me the 6 digit code sent to your phone to stop the fraud",
   "Your UPI PIN is required to receive {a}. Reply with your PIN {u}",
   "Send the verification code you received to confirm your refund of {a}"],
 "account_verification": ["Your email password expires today. Verify your account to keep access {l}",
   "Security alert: sign-in from a new device. Verify it was you or your account will be locked {l}",
   "Your Microsoft 365 mailbox is full. Re-validate your credentials {u} {l}",
   "Action required: confirm your identity to avoid suspension of your Netflix account {l}"],
 "legitimate": ["Hey, are we still meeting for lunch tomorrow at 1?", "Your OTP for login is 482913. Do not share this with anyone. - {b}",
   "Hi team, please find attached the agenda for Monday's project review meeting.", "Your order #48213 has shipped and will arrive on Friday. Track it in the app.",
   "Reminder: your dentist appointment is on Thursday at 4 pm.", "Thanks for your payment of {a}. Your receipt is available in your account dashboard.",
   "Can you review my pull request when you get a chance? No rush.", "Happy birthday! Hope you have a great day with family.",
   "Your electricity bill for September is generated. Pay by the due date through the official app.", "Lecture notes for Data Structures are uploaded on the college portal.",
   "Mom: Please buy some milk and bread on your way home.", "Your monthly statement is ready. Log in to the official website to view it.",
   "Class is rescheduled to 11 am. Please inform your classmates.", "Meeting invite: Weekly sync, Tuesday 10:30. Zoom link in the calendar event.",
   "Your cab is arriving in 3 minutes. Driver: Ravi, OD 02 AB 1234.", "Congratulations on your promotion! Dinner is on me this weekend."],
}
FILL = ["", "Thank you.", "Regards, Support Team", "Do not ignore this message.", "Act fast!", "Hurry!", "Sent via secure portal."]


def make(label):
    t = R.choice(T[label])
    s = t.format(b=R.choice(BANK), u=R.choice(URG), l=R.choice(LINK).format(b=R.choice(["hdfc", "paypal", "sbi"])), a=R.choice(AMT))
    if R.random() < .3: s = s.upper() if R.random() < .15 else s
    if R.random() < .4: s += " " + R.choice(FILL)
    if R.random() < .2: s = s.replace(" a", " a ", 1).replace("  ", " ")
    return s.strip()


def main(n=260):
    rows = []
    for label in T:
        rows += [(make(label), label) for _ in range(n * (2 if label == "legitimate" else 1))]
    # 5% label noise + light word dropout so scores reflect realistic, imperfect data
    labels = list(T)
    rows = [(" ".join(w for w in t.split() if R.random() > 0.08), R.choice(labels) if R.random() < 0.05 else l) for t, l in rows]
    R.shuffle(rows)
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["text", "label"]); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
