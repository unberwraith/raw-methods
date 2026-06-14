Introdcution to L4 DDoS after the basics.

The types of L4 DDoS attacks: Spoof & Raw.

Spoof:
A spoofed ddos attack is made ONLY with the help of a server that has IPHM ( IP Header modification ) enabled, and the provider need to have BCP38 filtering turned off.
It is designed to hide the origin of the attacker. It is hard to impossible to track a spoofed ddos attack by just looking at the logs, because all IPS from there are spoofed.
A simple spoof attack is not very big, thats where amplification comes into play. Amplification is a tehnique used by ddosers where they create a method, lets take DNS for example, and its not just spoofing anymore, its multiplying the attack. By spoofing, it can mimic the victim IP and trick the third-parties dns servers into thinking that the victim asked for the gbps/pps, when in reality, the victim did nothing. Example: Victims ip 50.50.50.50 , dns server ip 70.70.70.70, the attacker will make the dns server to think that the 50.50.50.50 wants data , and they ask: I want 30 gbps for 60 seconds please, dns says okey, im sending it right now. And the victim see's in the logs 30gbps from 70.70.70.70 for 60 seconds, while they didnt asked for anything.
Amplification its very easy to block since they can see incoming dns traffic from a big payload such as: .ANY or TXT record query.
How do they find these servers you are going to ask. Well, zmap has its role as well. Zmap is a network tool that is used to scan billions of IPs in hours. An attacker can scan for DNS reflectors with a bulletproof vps in less than 10 hours and find over 20k good reflectors ( dns servers ) that can be used for an amplified attack.
The amplification factor means how big the amplification of the attack can be. For example DNS, it can range average from 28x to 54x, while there are other protocols such as NTP where the amp factor can range between 100x and can reach even 1000x stable.
Some servers can have a very big amp factor, like the dns can have up to 70x, but not for a long time because of the rate-limit most of the time.

RAW:
A raw attack can be made from almost anything that has a internet connection, its very compatible and easier to perform rather than a spoofed one.
A raw ddos attack can be made by: finding a bulletproof hosting provider, getting a mirai based source, finding a good exploit, infecting devices, and running the methods.
Depending on the exploit, you can get many bots that are not dying that fast with good output, or servers that after 10 attacks are gone.
Very important is to never buy exploits from random guys, because 99.99% of the time, they are scammers.
Another important thing is for you to realize that any exploit can get patched at any moment, and in max 5 months, the devices will get security updates and you will remain with 0 bots.
Tips: Never put the len above 700-800, that can kill many bots. Never share anything with anyone. Everytime check for newer and newer CVE's.
A raw attack is much harder to detect and to block, since if its infecting real devices, it looks like real home, residentials IPs.

Do you think that if you know these you can safely start a C2/Botnet and start selling? No.
Most of the time, people think they can just learn some basic stuff and hope for big profits ( that's why most of the time c2s exit scam or close their project ).
Because they are only learning, not practicing. And the only way to learn real stuff is to practice.
Always learn the most current stuff, never stay in the past with security and tehnology, because its evolving faster than you think.
Always practice and practice, never think that you learn something and you are done, no. You will see that you actually dont know anything.

Why would someone DDoS you will maybe ask, well they will DDoS for 2 main reasons: fun, and money.
How are they making money? Blackmailing. Basically telling people to pay them or they will ddos them.
Fun, ddosing game servers, websites, because they think they are someone when in reality even a down syndrome human can create this.
DDoS-ing is not a cool ability that a human can learn and practice, its just a way to learn the top of the icebearg about security, and maybe wishing for a soc analyst/network analyst job.
DDoS-ing can get u up to 10 years in prison, so do that with this in mind, and NEVER think you are safe, many people from com got fedded and they thought the same thing.

I tried my best to explain, I hope you understood.
Stay safe, Unber.