# Beginner Guide

This guide has five steps. Do them in order.

Each step has three parts:

* **What to do**
* **What you should see**
* **If it does not work**

You do not need to know any programming. You do not need Git. You do not need
to type Python commands.

Linux is shown first because Linux is where Eye for an Eye does everything it
can do. Windows is shown too, and it does less.
[What is different](#what-windows-can-and-cannot-do) is at the end.

---

## What This Program Does

Eye for an Eye watches the visitors to a website or a server.

It looks at *how* someone behaves: how fast they ask for pages, and how many
different pages they ask for. It writes notes about what it saw.

**It does not block anyone.** Not at first. Blocking is a separate thing you
have to switch on yourself, on purpose, after telling it which addresses it must
never block.

Two words used below:

* **Safe Monitoring**: watching and writing notes. Nobody is blocked.
* **Automatic Protection**: really blocking visitors. It is off. It is an
  advanced step for later, and it is Linux only.

---

## Step 1: Install

### What to Do

**Linux:** open a terminal in the folder you unpacked and run

```sh
sh install.sh
```

**Ubuntu 24.04 with the Debian package instead:**

```sh
sudo apt install ./eye-for-an-eye_<version>_all.deb
```

Use the real filename from the release page.

**Windows:** double-click `Install-EyeForAnEye.cmd`

### What You Should See

```
==> Installation complete (installer version 2)

  Mode:               Safe Monitoring
  Automatic blocking: OFF
  Firewall changed:   NO
  Started:            NO
```

It then tells you the two commands to run next.

### If It Does Not Work

| It says | What to do |
| --- | --- |
| Python 3.12 is required | On Ubuntu: `sudo apt install python3.12 python3.12-venv`. On Debian: install [uv](https://docs.astral.sh/uv/) and run the installer again. On Windows: install Python 3.12 from python.org and tick "Add python.exe to PATH". |
| cannot write in *some directory* | That directory belongs to another account. Do not re-run the whole installer with `sudo`. |
| Could not finish installing | Check the Internet connection and try again. |
| `eye-for-an-eye: command not found` afterwards | Add `~/.local/bin` to your `PATH`, or use the full path the installer printed. |
| the Debian package refuses to install | Your system Python is not 3.12. Use `sh install.sh` instead. |

The installer never asks for Administrator or `sudo` unless you asked for
`--system`. If something asks you for a password that this page did not mention,
stop and find out what is asking.

More detail: [Install on Linux](INSTALL_LINUX.md).

---

## Step 2: Check the Installation

### What to Do

**Linux:**

```sh
eye-for-an-eye check-install
```

**Windows:** double-click `Status-EyeForAnEye.cmd`

### What You Should See

```
  [yes] the program is installed
  [yes] a settings file exists
  [yes] the settings are valid
  [yes] automatic blocking is off
  [NO ] a traffic source is chosen
```

That last `NO` is expected right now. Step 3 fixes it.

### If It Does Not Work

It prints the line that says `NO` and what to do about it. Read that line.

The line *the learning part is available* may say `NO`. That is fine. Eye for an
Eye works without it.

---

## Step 3: Choose What to Watch

This is the step most people need. Until you do it, the status says
**NEEDS SETUP**.

### What to Do

```sh
eye-for-an-eye setup
```

It asks you:

```
What do you want Eye for an Eye to watch?

  1. A website log   — the file your web server writes about visitors
  2. Network traffic — Linux only, needs an extra helper program
  3. Nothing yet     — just try the demo first
```

Type `1` and press Enter. Then it asks where your website log is, shows you the
files it can find on this computer, and **checks your answer before accepting
it**.

You never have to edit a settings file by hand.

If you already know the path, you can say it all at once:

```sh
eye-for-an-eye setup --watch website-log --access-log /var/log/nginx/eye-for-an-eye.log
```

### What You Should See

```
Eye for an Eye will watch:
  /var/log/nginx/eye-for-an-eye.log

Start it when you are ready:
  eye-for-an-eye start
```

### If It Does Not Work

**"That file is not in the format Eye for an Eye reads."**

This is the most common one, and it is worth reading carefully.

Eye for an Eye reads one JSON line per visit. Most web servers write something
else by default. A normal Nginx `access.log` will not work. Every line would be
thrown away.

To get a file it can read, run:

```sh
eye-for-an-eye web log-format
```

That prints the settings to add to Nginx, and the name of the new file it will
write. Add them, check with `nginx -t`, reload Nginx, then run `setup` again and
give it the **new** file.

That command only prints text. It changes nothing.

**"Eye for an Eye is not allowed to read that file."**

The account running Eye for an Eye does not own the log. With Nginx on Debian or
Ubuntu:

```sh
ls -l /var/log/nginx/            # see which group owns it
sudo usermod -aG adm "$USER"     # then log out and back in
```

Do not `chmod 777` the log. Do not run Eye for an Eye as root to read it.

**"There is no file at that path."** Check the spelling.

### The Other Choice: A Network Sensor

This watches network packets directly. It is **Linux only** and it needs a second
helper program that is allowed to read from the network card. `setup` will record
your answer and tell you what is still missing.

This is not a beginner path. If you want it, read
[PRIVILEGES.md](PRIVILEGES.md) and [INSTALL.md](INSTALL.md).

---

## Step 4: Start Watching

### What to Do

**Linux:**

```sh
eye-for-an-eye start
```

**Windows:** double-click `Start-EyeForAnEye.cmd`

### What You Should See

```
Eye for an Eye is watching.

  Mode:               SAFE MONITORING
  Automatic blocking: OFF
  Watching:           /var/log/nginx/eye-for-an-eye.log

Nothing is blocked. Press Ctrl+C to stop.
```

Then, as visitors arrive, lines like:

```
  14:22:05  visitors seen: 3   notes written: 7   blocked: 0
```

`blocked: 0` will stay `0`. Safe Monitoring does not block.

Leave the window open. Closing it stops the watching.

To check from another terminal:

```sh
eye-for-an-eye status
```

### If It Does Not Work

| It says | What to do |
| --- | --- |
| is not set up on this computer yet | It could not find a settings file. It prints where it looked. Run `eye-for-an-eye setup`. |
| does not know where to watch yet | Go back to Step 3. |
| This settings file has automatic blocking switched on | You are not in Safe Monitoring. Read [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md) before going further. |
| Watching network packets does not work on this kind of computer | You are on Windows and chose the network sensor. Use a website log instead. |
| It runs, but `visitors seen` stays at 0 | Usually the log format. See Step 3. Run `eye-for-an-eye web doctor`. It says how many lines it could not read. |

---

## Step 5: Stop

### What to Do

**Linux:**

```sh
eye-for-an-eye stop
```

**Windows:** double-click `Stop-EyeForAnEye.cmd`

Pressing **Ctrl** and **C** together in the *watching* window also works, and so
does closing that window.

### What You Should See

```
Asking Eye for an Eye to stop.

Stopped. Nothing is blocked.
```

It can take a few seconds. Stop asks the watching program to finish. The program
notices the next time it looks, which is every few seconds.

Afterwards, the status says:

```
  Protection:         NOT RUNNING
```

### If It Does Not Work

If Stop says it has not stopped yet, wait a moment and run the status again.

Closing the *watching* window always stops it. On this path Eye for an Eye
installs no background service, so there is nothing hidden left running.

Stop never ends any other program on your computer. It asks only its own.

---

## Try It Without a Website: The Demo

You can prove the installation works without any visitors at all.

**What to do**

```sh
eye-for-an-eye easy demo
```

On Windows, double-click `Demo-EyeForAnEye.cmd`.

**What you should see**

```
Demo complete.

  1 test event processed.
  No network block was created.
  Nothing outside this computer was contacted.
```

It makes one pretend visitor on your own computer, thinks about it, writes one
note, and stops. It touches no firewall and contacts nothing outside your
machine.

For everything the demo actually did, add `--advanced`.

---

## Where Your Files Are

On Linux this depends on how you installed. The installer wrote the exact paths
into `install-report.txt`, and `eye-for-an-eye check-install` prints the settings
file it is using.

| What | Linux (`sh install.sh`) | Windows |
| --- | --- | --- |
| Settings | `~/.local/share/eye-for-an-eye/data/eye-for-an-eye.toml` | `%LOCALAPPDATA%\eye-for-an-eye\eye-for-an-eye.toml` |
| Notes and records | `~/.local/share/eye-for-an-eye/data` | `%LOCALAPPDATA%\eye-for-an-eye\data` |
| Install report | `~/.local/share/eye-for-an-eye/install-report.txt` | `%LOCALAPPDATA%\eye-for-an-eye\install-report.txt` |
| The program itself | `~/.local/share/eye-for-an-eye/venv` | `%LOCALAPPDATA%\eye-for-an-eye\runtime` |

Installed from the Debian package instead? The paths are different and
[INSTALL_LINUX.md](INSTALL_LINUX.md) lists all of them.

---

## Removing It

**Linux, installed with `install.sh`:**

```sh
sh uninstall.sh
```

**Linux, installed from the Debian package:**

```sh
sudo apt remove eye-for-an-eye
```

**Windows:** double-click `Uninstall-EyeForAnEye.cmd`

**If you no longer have the files you unpacked**, this works on Linux and
Windows both, and lists exactly what it will remove before removing anything:

```sh
eye-for-an-eye easy uninstall
```

Your settings, notes and records are **kept**. They are yours.

To remove those as well, use `sh uninstall.sh --purge`, or add
`--also-remove-my-records` to `easy uninstall`. Deleting them cannot be undone,
which is why it is a separate thing to ask for.

`apt remove` and `apt purge` both leave your settings and records alone. The
package does not own those paths.

Uninstalling does not change your firewall. Eye for an Eye never changed it,
unless you switched Automatic Protection on yourself.

---

## What Windows Can and Cannot Do

| | Linux | Windows |
| --- | --- | --- |
| Watch a website log | Yes | Yes |
| The demo | Yes | Yes |
| Watch network packets | Yes, with a helper program | No |
| Automatic blocking | Yes, when you configure it | No |
| Run as a background service | Yes, with systemd | No |

Windows is fine for trying Eye for an Eye and for watching a website log. A
server you want protected properly should be Linux.

---

## Trouble

| Problem | Try this |
| --- | --- |
| It does not start. | Run the status. Read the message it shows. |
| It says NEEDS SETUP. | Go to Step 3 and choose what to watch. |
| No visitors are showing. | Almost always the log format, not the path. See Step 3. |
| `command not found`. | Add `~/.local/bin` to your `PATH`. |
| Automatic Protection will not start. | That is on purpose. It needs to know which addresses must never be blocked. See below. |
| Something I do not understand. | [Troubleshooting](TROUBLESHOOTING.md), then `eye-for-an-eye doctor`. Send that output and `install-report.txt` to whoever helps you. |

Never send anyone your passwords, your login cookies, or your visitors'
traffic. Nobody helping you needs those, and Eye for an Eye never asks for them.

---

## Common Questions

**Does it need cloud AI or an account?** No. Nothing is sent anywhere. There is
no account, no API key and no subscription. The optional local model runs on your
own machine.

**Does it block automatically?** Not unless you configure Automatic Protection
yourself, and that is Linux only.

**Does it work without the machine-learning part?** Yes. The mathematical engine
works alone. `check-install` saying the learning part is not available is fine.

**Can it read Nginx and Apache logs?** It reads one JSON object per line. You can
set up Nginx to write that. `eye-for-an-eye web log-format` prints how. You can
set up Apache in a similar way, but only the Nginx recipe is tested.

**Does it need root?** No. Installing, setup, starting, status, the demo and
uninstalling all run as a normal user. Only two things need more: the packet
capture helper needs one narrow permission, and changing the firewall needs root.
Never run the whole thing as root.

**How do I stop it?** `eye-for-an-eye stop`, or close the watching window.

**Where is my data?** On your machine only, in the paths listed above.

**Can I uninstall it?** Yes, and it tells you what it will remove first.

---

## About Automatic Protection

This part is not for beginners, and the warning is deliberately not simplified.

Automatic Protection lets Eye for an Eye add temporary blocks to your computer's
firewall by itself. A wrong block stops a real person from reaching your
website, silently, with no way for them to appeal. The people most affected
are those on unusual networks, and those who use assistive software.

Before it will start, you must tell Eye for an Eye which network addresses it
must **never** block. These are the addresses you use to administer the machine.
Without that list it refuses to start, because it could otherwise lock you out of
your own server. It will not guess the list for you.

It is Linux only.

Two more things worth knowing before you consider it:

* Eye for an Eye has **not** been tested against real Internet traffic yet. What
  it would block, and how often it would be wrong, is unmeasured. See
  [VALIDATION_STATUS.md](VALIDATION_STATUS.md).
* Every block is temporary and expires by itself.

To see what is still missing:

```sh
eye-for-an-eye autonomy readiness
```

If you still want it, read [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md) all the way
through first.

Safe Monitoring is the right place to stay until then. It is useful on its own:
it shows you what your traffic looks like, and it cannot hurt anyone.
