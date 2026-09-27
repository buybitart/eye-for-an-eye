# Start here

Eye for an Eye watches a website or a server.

It writes notes about who visits. It does **not** block anyone.

Blocking is off. You have to turn it on yourself, later, on purpose.

---

## Linux

This is the main way to use Eye for an Eye.

### 1. Check the download

```sh
sha256sum -c SHA256SUMS
```

You want to see `OK`. If you see `FAILED`, download it again.

### 2. Install

```sh
sh install.sh
```

Wait. It can take a few minutes.

Look for the words **Installation complete**.

### 3. Choose what to watch

```sh
eye-for-an-eye setup
```

It asks you a question and checks your answer.

### 4. Start

```sh
eye-for-an-eye start
```

You should see **Eye for an Eye is watching**.

Leave that window open. Closing it stops the watching.

### 5. Check

```sh
eye-for-an-eye status
```

You should see:

```
  Protection:         WATCHING
  Mode:               SAFE MONITORING
  Automatic blocking: OFF
```

### 6. Try it without a website

```sh
eye-for-an-eye easy demo
```

You should see **Demo complete**. It uses a pretend visitor. It blocks nobody.

### 7. Stop

```sh
eye-for-an-eye stop
```

You should see **Stopped**. It can take a few seconds.

### 8. Remove it

```sh
sh uninstall.sh
```

Your notes and settings are kept. Add `--purge` to delete those too.

---

## Windows

Windows can watch a website log and run the demo. It cannot watch network
packets and it cannot block. Linux does more.

1. Double-click `Install-EyeForAnEye.cmd` and wait for **Installation complete**.
2. Double-click `Start-EyeForAnEye.cmd`.
3. Double-click `Status-EyeForAnEye.cmd`.
4. Double-click `Demo-EyeForAnEye.cmd` to try it without a website.
5. Double-click `Stop-EyeForAnEye.cmd`.
6. Double-click `Uninstall-EyeForAnEye.cmd` to remove it. It tells you what it
   will remove **before** it removes anything.

---

## If it says NEEDS SETUP

That means it does not know **where** to watch yet.

Pick one:

* **A website log.** Easiest. Works on Windows and Linux.
* **A network sensor.** Linux only. Needs an extra helper program.

Run `eye-for-an-eye setup` and it will ask.

The next page shows you how: **[Beginner guide](docs/BEGINNER_GUIDE.md)**

---

## If something goes wrong

Run the check:

```sh
eye-for-an-eye check-install
```

On Windows, double-click `Status-EyeForAnEye.cmd`.

It says what is missing in plain words. If that is not enough:
**[Troubleshooting](docs/TROUBLESHOOTING.md)**

If you need help, send the file `install-report.txt`.
It has no passwords in it and no visitor traffic.

---

## One warning, said plainly

Later you may read about **Automatic Protection**. That is different.

Automatic Protection can change your computer's firewall and can stop real
people from reaching your website. It will not start until you have told it
which addresses it must never block — otherwise it could lock you out of your
own machine. That is a safety rule and it cannot be skipped.

It is Linux only. Nothing in the steps above can turn it on.

---

Next: **[Beginner guide](docs/BEGINNER_GUIDE.md)** — the same steps, with more
help at each one.

Installing in detail: **[Install on Linux](docs/INSTALL_LINUX.md)**

Developers: see [README.md](README.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).
