Types of Vulnerabilities
Vulnerabilities are weaknesses or flaws in systems, applications, or infrastructures that can be exploited
by malicious individuals to compromise the security of a system or cause damage. These vulnerabilities
can exist due to design, implementation, or configuration errors and can be exploited to access, modify,
or destroy information, disrupt services, execute malicious code, or perform other harmful activities.
Vulnerabilities are weaknesses that can compromise security. It is important to understand the basic
concepts of security and vulnerabilities to identify, fix, and prevent threats and attacks on a system
or application.
The following are the topics that we will cover in the chapter:
• Software vulnerabilities
• Network vulnerabilities
• Configuration vulnerabilities
• Zero-day vulnerabilities
• Hardware vulnerabilities
• Social vulnerability
The following skills can be gained from reading this chapter:
• Understanding the different categories of security vulnerabilities: From software vulnerabilities,
network vulnerabilities, and database vulnerabilities to physical vulnerabilities and other types
of vulnerabilities that can be exploited by attackers
• Recognizing specific characteristics and details of each type of vulnerability: How they
originate, what damage they can cause, and how they can be exploited by attackers
• Adopting best practices to mitigate or eliminate different vulnerabilities: How vulnerabilities
can be prevented or repaired to reduce the risk of attacks
After listing the different topics covered in this chapter, let’s begin!
68 Types of Vulnerabilities
Software vulnerabilities
Software vulnerabilities are weaknesses or flaws in the design, implementation, or configuration of
a program that can be exploited by attackers to compromise the security of the system on which the
software runs. These vulnerabilities can be used to access, modify, or delete data, gain unauthorized
privileges, or cause damage to affected systems.
These are vulnerabilities present in applications and operating systems. They may be due to programming
errors, lack of input validation, and memory management problems, among others. Attackers can
exploit these vulnerabilities to execute malicious code, access sensitive data, or take control of the
compromised system.
The following are important aspects related to software vulnerabilities:
• Types of software vulnerabilities
• Patches and updates
• Shared responsibility
• Audits, security testing, and bug bounties
• Disclosed liability
We have seen an overview of software vulnerabilities. We will now explain each of them.
Types of software vulnerabilities
There are many types of software vulnerabilities; the following are the most common and most
exploited by cybercriminals:
• Buffer overflow: Occurs when a program allows more data to be written to a buffer (temporary
memory) than it can hold, which can result in the execution of malicious code. The following
is a code extract of a stack buffer overflow:
#include <cstring>
#include <iostream>
int main() {
char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char buffer[10];
strcpy(buffer, payload);
printf(buffer);
return 0;
}
• Code injection: This occurs when untrusted data is inserted into a program and executed as
commands, which can allow an attacker to execute arbitrary code on the system.
Software vulnerabilities 69
• Cross-site scripting (XSS): A common vulnerability in web applications where attackers insert
malicious scripts into web pages that are then executed by users’ browsers.
• SQL injection: Occurs when malicious SQL statements are inserted into input fields of a web
application, allowing an attacker to access or manipulate the site’s database.
We will talk in much more detail about these types of vulnerabilities in the following chapters, especially
the most frequent ones in bug bounty programs, such as web and mobile device vulnerabilities.
Important note
It is essential to understand that threats and vulnerabilities are not identical concepts. Threats
refer to malicious or dangerous actions that can exploit vulnerabilities present in a system
or software. In other words, threats are potential attacks that exploit weaknesses or flaws in
the design or implementation of software to compromise its security. Therefore, knowing
the difference between the two terms is essential to understanding how attackers can exploit
vulnerabilities in their attempt to damage or illegally access systems and data.
Patches and updates
Software developers and operating system manufacturers regularly release patches and updates to fix
known vulnerabilities. It is critical to keep your software up to date to protect against the latest threats.
Shared responsibility
Both developers and users have a responsibility to address software vulnerabilities. Developers must
follow secure coding practices, perform rigorous testing, and respond quickly to vulnerability reports.
Users, on the other hand, must be vigilant about updates and patches and take steps to protect themselves.
Audits, security testing, and bug bounties
Audits, security testing, and bug bounties are essential to identify and address vulnerabilities in a
system or application. These tests enable organizations to better understand their security posture
and take corrective action.
Disclosed liability
When a vulnerability is discovered, there is an ethical debate about how and when to disclose it.
Disclosed liability involves researchers informing manufacturers or developers about the vulnerability
so that they can fix it before it is made public.
Having covered software vulnerabilities, the following section of this chapter will delve into the topic
of network vulnerabilities.
70 Types of Vulnerabilities
Network vulnerabilities
A network vulnerability is a weakness or flaw in the security of a system or network infrastructure
that could be exploited by attackers to compromise the integrity, confidentiality, or availability of data
and resources. This type of vulnerability can be exploited by cybercriminals or attackers in order to
compromise security and gain access to confidential information or perform malicious activities.
These vulnerabilities can be caused by a variety of factors, such as design errors, insecure configurations,
software flaws, lack of security patches, and more. The following are important aspects relating to
network vulnerabilities:
• Types of network vulnerabilities
• Impact of vulnerabilities
• Vulnerability assessments
• Security practices
• Proactive cybersecurity
We have seen some details of network vulnerabilities. We will now explain each of them.
Types of network vulnerabilities
There are different types of network vulnerabilities, such as those related to the operating system,
applications, network protocols, misconfigurations, lack of security patches, and more. Some specific
vulnerabilities include denial-of-service (DoS) attacks and exploitation of open ports.
Impact of vulnerabilities
Network vulnerabilities can have serious consequences, such as leakage of confidential data, service
disruptions, loss of productivity, damage to company reputation, and possibly even unauthorized
access to critical systems.
Vulnerability assessments
Organizations often conduct vulnerability assessments to identify and address potential weaknesses in
their networks and systems. This involves regular security scans, penetration testing, and risk analysis
to detect and correct vulnerabilities before they are exploited.
Security practices
To reduce the risk of network vulnerabilities, organizations should implement robust security practices,
such as network segmentation, constant monitoring, cybersecurity education for staff, and the use of
security solutions such as firewalls and intrusion detection systems (IDSs).
Configuration vulnerabilities 71
Proactive cybersecurity
As cyber threats are constantly evolving, it is crucial to take a proactive approach to cybersecurity.
This involves keeping abreast of the latest cybersecurity threats and trends, implementing mitigation
measures, and preparing to respond effectively in the event of a security incident.
That covers network vulnerabilities; in the next part of this chapter, we will talk about
configuration vulnerabilities.
Configuration vulnerabilities
Configuration vulnerabilities refer to errors or misconfigurations in systems, applications, or devices
that can be exploited by attackers to compromise security and gain access to sensitive information,
resources, or functions that should not be accessible to them. These vulnerabilities often result from
improper configuration practices or lack of attention to security best practices. Here are some examples
of common configuration vulnerabilities:
• Weak or default passwords
• Excessive permissions and access
• Unnecessary open services and ports
• Lack of encryption
• Weak security configurations
• Updates and patches not applied
• Lack of security audits
• Insecure default configurations
• Lack of multi-factor authentication (MFA)
• Exposure of sensitive files and directories
We have seen some examples of configuration vulnerabilities. We will now explain each of them.
Weak or default passwords
If administrators do not change default passwords or use weak and easy-to-guess passwords, attackers
can easily gain access to systems and devices.
Excessive permissions and access
Granting unnecessary permissions to users or applications can expose data and resources to unnecessary
risks. Attackers can exploit these excessive privileges to gain unauthorized access.
72 Types of Vulnerabilities
Unnecessary open services and ports
Keeping unused or unnecessary services and ports open can provide additional entry points for
attackers. Every open service or port is a potential attack vector.
Lack of encryption
If data is transmitted or stored unencrypted, attackers could intercept or access sensitive information.
A lack of encryption can also expose passwords and credentials.
Weak security configurations
Poorly defined firewall configurations, access rules, and security policies can allow attackers to bypass
security measures and gain access to the network or systems.
Updates and patches not applied
Failure to keep systems and applications up to date with the latest security patches can leave known
vulnerabilities uncorrected.
Lack of security audits
Failure to conduct regular security audits to identify and correct configuration issues can result in the
persistence of undetected vulnerabilities.
Insecure default configurations
Using default configurations that do not follow security best practices can expose systems to
unnecessary risk.
Lack of MFA
A lack of MFA allows attackers to access accounts using only one password, even if it is stolen.
Exposure of sensitive files and directories
Failure to adequately protect sensitive files and directories can allow attackers to access
confidential information.
That covers configuration vulnerabilities; in the next part of this chapter, we will talk about
zero-day vulnerabilities.
Zero-day vulnerabilities 73
Zero-day vulnerabilities
A zero-day vulnerability is a weakness in a software system that is unknown to the software manufacturer
and therefore has not been patched or fixed. This means that developers and users do not have time
to prepare before attackers discover and exploit the vulnerability. The term zero-day comes from the
fact that defenders do not have zero days in advance to prepare before attacks are made.
Zero-day vulnerabilities are particularly dangerous because cybercriminals can exploit them before
a fix has been developed and distributed. This can allow them to carry out sophisticated and often
devastating attacks. Here are some key points to better understand zero-day vulnerabilities:
• Secret discovery
• Targeted attacks
• Security threats
• Patches and mitigations
• Black market value
We have seen an overview of zero-day vulnerabilities. We will now explain each of them.
Secret discovery
Attackers or security researchers can discover these vulnerabilities without disclosing them to the
developing company or the community at large. Also, these types of vulnerabilities can be discovered
by cybercriminals with malicious intent.
Targeted attacks
Zero-day vulnerabilities are often used in targeted attacks, where cybercriminals specifically target a victim
or group of victims. This can include attacks on particular companies, governments, or organizations.
Security threats
Zero-day vulnerabilities can affect a wide variety of systems and software, such as operating systems,
software applications, web browsers, and internet-connected devices. This can result in data theft,
disruption of services, unauthorized access to systems, and other types of security compromises.
Patches and mitigations
Once a zero-day vulnerability is discovered, manufacturers and developers work quickly to develop
security patches to correct the problem. However, until these patches are available and deployed,
systems remain vulnerable.
74 Types of Vulnerabilities
Black market value
Zero-day vulnerabilities are highly valued on the black market where malicious actors can buy or
sell them for large sums of money. For these cybercriminal groups, they offer you the opportunity to
perform highly effective attacks before proper security measures are implemented.
That covers zero-day vulnerabilities; in the next part of this chapter, we will talk about
hardware vulnerabilities.
Hardware vulnerabilities
Hardware vulnerabilities are flaws or weaknesses in the physical components of a computer system
that can be exploited by attackers to compromise the security and integrity of data or system operation.
These vulnerabilities can arise due to design errors, problems in manufacturing, or even inherent
characteristics of the components that can be maliciously exploited.
Here are some examples of hardware vulnerabilities that have been highlighted in the past:
• Spectre and Meltdown
• Rowhammer
• BadUSB
• Malicious firmware
• Attacks on Internet of Things (IoT) devices
• Smart card attacks
• Vulnerabilities in medical devices
• Physical attacks
• Side-channel attacks
• Hacker toys
We have discussed some hardware vulnerabilities. We will now explain each of them.
Spectre and Meltdown
These are two of the most notorious hardware vulnerabilities discovered in recent years. They
affected a wide range of processors, including those manufactured by Intel, AMD, and ARM. These
vulnerabilities allowed attackers to access sensitive data in system memory, including passwords and
other confidential data.
Hardware vulnerabilities 75
Rowhammer
This vulnerability exploits a weakness in the RAM architecture. By executing specific memory access
patterns, attackers can alter bits in adjacent memory cells, which can lead to data corruption and, in
some cases, malicious code execution.
BadUSB
This vulnerability is based on the manipulation of USB devices. An attacker can modify a USB device
so that, when connected to a computer, it acts as a malicious device that can perform unauthorized
actions, such as installing malware or stealing data.
Malicious firmware
Electronic devices, such as computers and mobile devices, have firmware that controls their basic
operation. If an attacker manages to compromise the firmware, they can have full control over the
device without being easily detected. This can result in the persistent installation of malware or the
disabling of security features.
Attacks on IoT devices
IoT devices are often resource-constrained and may lack strong security measures. This makes them
vulnerable to attacks that compromise their functionality and can be used to access the network they
are connected to.
Smart card attacks
Smart cards, such as credit cards with EMV (Europay, MasterCard, and Visa), chips, can also be
vulnerable. Attackers may attempt to breach security measures on the card to conduct fraudulent
transactions or access sensitive information.
Vulnerabilities in medical devices
Medical devices, such as pacemakers and attached insulin pumps, can also be targets of attacks.
Vulnerabilities in these devices could have serious consequences for patients’ health.
Physical attacks
Even physical access to a device can lead to vulnerabilities. Attackers may attempt to bypass passwords
or security measures by directly accessing hardware components.
76 Types of Vulnerabilities
Side-channel attacks
These attacks are based on exploiting information leaked during the execution of operations on a
device. Examples include attacks based on power consumption, instruction execution time, or even
electromagnetic noise emitted by a device.
Hacker toys
Talking about hardware has reminded me about hardware devices that I have used as well as most of
my fellow hackers, such as so-called hacker toys.
It is important to emphasize the ethical considerations and legal limits of their use.
These types of devices or toys are designed to breach systems and penetrate them. I would like to
mention them a little more in the following table:
Product Description URL
LAN TURTLE Provides stealthy remote access,
network intelligence gathering, and
surveillance capabilities.
https://shop.hak5.
org/products/lan-turtle
BASH BUNNY The world’s most advanced USB
attack platform.
https://shop.hak5.
org/products/bashbunny
KEY CROC A keylogger armed with pentest tools,
remote access, and payloads.
https://shop.hak5.
org/collections/sale/
products/key-croc
PACKET SQUIRREL Hak5’s Packet Squirrel is a stealthy
man-in-the-middle (MitM) pocket.
https://shop.hak5.
org/products/packet-
squirrel
SHARK JACK For social engineering engagements and
opportunistic audits of wired networks.
https://shop.hak5.
org/collections/sale/
products/shark-jack
WIFI PINEAPPLE This toy will help you with Wi-Fi audits. https://shop.hak5.
org/products/
wifi-pineapple
SCREEN CRAB Covert inline screen grabber that
is placed between HDMI devices,
such as a computer and a monitor,
or a console and a TV, to capture
screenshots silently.
https://shop.hak5.
org/collections/sale/
products/screen-crab
Hardware vulnerabilities 77
Product Description URL
KEYSY Backs up to four RFID access credentials
in a small keychain form factor.
https://shop.hak5.
org/collections/
featured-makers/products/
keysy
RUBBER DUCKY Injects keystrokes at superhuman
speeds, violating inherent trust.
https://shop.hak5.
org/products/usb-rubber-
ducky
Alfa 802.11b/g/n Wi-Fi antenna for wireless audits. https://www.tienda-
alfanetwork.com/
alfa-awus1900-antenawifi-
usb-ac1900-doble-
banda-dual.html
SouthOrd 14 Piece
Lock Pick Set
For physical penetration tests. https://hackerwarehouse.
com/product/
southord-14-piecelock-
pick-set/
USB Ninja Cable It functions as a normal USB cable
(both power and data) until a wireless
remote control activates it to deliver
the attack payload of your choice to the
host machine.
https://hackerwarehouse.
com/product/
usb-ninja-cable/
KeyGrabber These are physical hardware keyloggers
that are completely transparent from
computer operation, and no software
or drivers are required. International
keyboard layouts are also supported.
https://hackerwarehouse.
com/product/
keygrabber/
Proxmark3
NFC RFID
Card cloner. https://proxmark.com/
HACKRF Software-defined radio. https://shop.hak5.
org/collections/
featured-makers/products/
hackrf
UBERTOOTH ONE Open source Bluetooth test tool. https://shop.hak5.
org/collections/
featured-makers/products/
ubertooth-one
78 Types of Vulnerabilities
Product Description URL
Flipper Zero Flipper Zero is a portable multi-tool in
the form of a toy for pentesters.
https://shop.flipperzero.
one/
O.MG Cables The O.MG Cable is a handmade USB
cable with an advanced implant hidden
inside. It is designed to allow your Red
Team to emulate attack scenarios of
sophisticated adversaries.
https://o.mg.lol/
Table 5.1 – Types of hacker toys
Important note
It’s important to clarify that sometimes, vulnerabilities found in IoT or medical devices are
based on software errors and not on the hardware.
After an insightful discussion about hardware vulnerabilities, in the next part of this chapter, we will
talk about social vulnerability.
Social vulnerability
Social vulnerability in the world of cybersecurity refers to the exploitation of human psychology and
social interactions to compromise the security of computer systems and gain unauthorized access to
sensitive information. Often, cybercriminals exploit people’s trust, naivety, or lack of knowledge to
deceive them and achieve their malicious goals.
Awareness and education are essential to address social vulnerabilities in cybersecurity. Organizations
and individuals must be alert to social engineering tactics and manipulation attempts. Cybersecurity
training can help individuals identify the signs of phishing and other attacks related to social
vulnerability. In addition, it is important to foster a culture of security where people feel comfortable
reporting potential attempts at deception or manipulation.
Examples of how social vulnerability in cybersecurity manifests itself include the following:
• Phishing
• Social engineering
• Social network attacks
• Infiltration of organizations
Social vulnerability 79
• Online influence and disinformation campaigns
• Privacy risks and publication of personal information
We have seen some examples of social vulnerabilities. We will now explain each of them.
Phishing
Phishing attacks involve sending fake emails that appear to come from legitimate sources, such as
banks or well-known companies. These emails often attempt to trick recipients into divulging sensitive
information, such as passwords or credit card numbers, by clicking on malicious links or providing
data in fake forms.
Social engineering
This approach is based on manipulating people into disclosing sensitive information or performing
actions that compromise security. Attackers can pose as technical support employees, co-workers, or
even friends to gain unauthorized access to systems or data.
Social network attacks
Social network profiles contain a lot of personal information, making them attractive targets for
cybercriminals. By obtaining personal information and social connections, attackers can execute
targeted attacks or trick people into clicking on malicious links.
Infiltration of organizations
Cybercriminals can impersonate legitimate employees or vendors to gain access to organizations’
systems and networks. They may use tactics such as sending fake emails to obtain login credentials
or introduce malware.
Online influence and disinformation campaigns
Social vulnerability can also manifest itself in the form of online disinformation and manipulation
campaigns. Malicious actors may use false or biased information to influence public opinion or
encourage unwanted actions.
Privacy risks and publication of personal information
People often share a large amount of personal information online without realizing the potential
risks. This information could be used by cybercriminals to carry out targeted attacks or identity theft.
80 Types of Vulnerabilities
Summary
We have reached the end of the chapter, in which you learned about the different types of existing
vulnerabilities such as software, network, configuration, zero-day, hardware, and social vulnerabilities.
In the future, cyber vulnerabilities will continue to be a major concern due to the continuing evolution
of technology and the complexities of cybercrime. Here are some perspectives on how vulnerabilities
could develop in the future:
• IoT
• Artificial intelligence (AI) and machine learning (ML)
In the next chapter, we will discuss the methodology of security testing.
