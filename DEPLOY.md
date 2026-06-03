# How to put changes live (from your phone)

You publish the app from **Termux** (the terminal app on your phone).
There are only **two** things to ever remember.

---

## ⭐ First time only (about 5 minutes)

Open Termux and run these three lines (copy/paste one at a time):

```
pkg install git -y
git clone https://github.com/Oxleymatt87/mini-crm.git
cd mini-crm
```

Then run the setup script — it installs everything and logs you in:

```
bash setup-termux.sh
```

When a link appears: open it in your browser, pick your Google account,
copy the code it gives you, and paste it back into Termux.

That's it. You're set up forever.

---

## 🚀 Every time you want to push changes live

Open Termux and run:

```
cd mini-crm
bash deploy.sh
```

When it finishes it prints your app's web address. Open it on your phone
and **pull down to refresh** — your changes are live. ✅

---

### If something goes wrong
Just tell Claude **"deploy isn't working"** and paste whatever Termux shows
on the screen. That's all the info needed to fix it.
