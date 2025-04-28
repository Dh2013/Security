testing.
6
Methodologies for
Security Testing
Security testing methodology, also known as penetration testing (pentesting) or vulnerability
testing, is a structured and planned approach to evaluating the security of an information system, web
application, network, or any other information technology element. The main objective of these tests
is to identify and remediate vulnerabilities that could be exploited by malicious attackers.
There are also official methodologies such as the Open Web Application Security Project (OWASP)
(https://owasp.org/www-project-web-security-testing-guide/), a guide that’s
followed by hundreds of professionals daily to perform security tests on web applications. OWASP
is a non-profit foundation. It works to improve security and is an invaluable tool for evaluating web
application security. If you want to dedicate yourself to bug bounty or web pentesting, the OWASP
guide will be your best friend. Always keep this guide close by – you will need it. Even if you have read it
twice in its entirety or are a senior pentester, you will have to consult this magnificent guide frequently.
There’s also a procedure you can follow to perform any pentest. This is linked to some daily actions
that any bug hunter will also have to follow. In this chapter, I will provide an overview of the key steps
and components of a typical security testing methodology, including the phases that are required to
perform a web pentest.
In addition, I will give you some recommendations from my experience and that of experienced
colleagues in the world of bug bounty hunting. This will give you a clear, orderly view of the target so
that you can automate your hunting tasks.
82 Methodologies for Security Testing
The following topics will be discussed in this chapter:
• Methodologies for pentesting
• Phases of a pentest
• Guidance and recommendations based on my experience
This chapter discusses the importance of following a structured and systematic approach to conducting
security testing: why it is important to follow a methodology and how it can help security researchers
more easily identify security vulnerabilities and risks. It will also help you understand the importance
of following a structured methodology for conducting security testing and how it can help identify
security vulnerabilities and risks more efficiently.
Methodologies for pentesting
When faced with the task of performing pentesting, we have a variety of methodologies from which we
can choose to follow or use as a guide when conducting audits. The choice depends on the individual
needs of each person involved in the bug bounty program.
Among the options available in the field of pentesting, there are the following methodologies:
• PTES: This is a methodology that provides a detailed framework for conducting pentesting. It
covers all phases, from planning to reporting and risk mitigation (http://www.penteststandard.
org/index.php/Main_Page).
• OWASP: OWASP offers a well-established methodology for testing web application security.
Its methodology focuses on identifying common vulnerabilities in web applications, such as
SQL injection, cross-site scripting (XSS), and improper access control (https://owasp.
org/www-project-web-security-testing-guide/latest/3-The_OWASP_
Testing_Framework/1-Penetration_Testing_Methodologies).
• OSSTMM: This is a set of guidelines and procedures for pentesting that focuses on measuring
security by assessing vulnerabilities and identifying weaknesses in security processes, systems,
and networks (https://www.isecom.org/OSSTMM.3.pdf).
• MITRE ATT&CK: This is a framework that focuses on tactics and techniques that are used by
adversaries rather than specific vulnerabilities. It is used to simulate cyberattacks and assess an
organization’s resilience to them (https://attack.mitre.org/):
Methodologies for pentesting 83
Figure 6.1 – The MITRE ATT&CK website
• Cyber Kill Chain: This is an approach with military roots that’s derived from the Kill Chain
concept. This methodology is based on the steps that threat actors typically follow when
executing persistent and advanced cyberattacks. Its purpose is to provide a more focused view
of the offensive aspect to advise companies on the security measures they should implement
at each stage to ensure their security (https://www.lockheedmartin.com/en-us/
capabilities/cyber/cyber-kill-chain.html).
• ISSAF: This is a methodology that focuses on the security assessment of enterprise
information systems. It provides detailed guidelines for conducting pentests and security
assessments (https://pymesec.org/issaf/).
• NIST: NIST provides guidelines for pentesting in its security documents, such as NIST
Special Publication 800-115. This methodology focuses on identifying and mitigating risks in
information systems and networks (https://www.nist.gov/itl/ssd/softwarequality-
group/computer-forensics-tool-testing-program-cftt/
cftt-general-0).
• Personalized methodologies: In addition to standard methodologies, security professionals
often adapt and customize their approaches to address the specific needs of their organizations or
projects. This may include combining multiple methodologies or creating a framework of their
own. Later, I will provide some tricks, tips, and guidance that I have picked up in my experience.
Now that we’ve discussed methodologies, we will talk about the various phases of a pentest.
84 Methodologies for Security Testing
Phases of a pentest
Security testing methodology, also known as pentesting or ethical security testing, is a structured and
planned approach to assessing the security of an information system, application, or network. The
main objective of these tests is to identify vulnerabilities and weaknesses that could be exploited by
malicious actors, and then provide recommendations for improving security.
Here, we can follow these steps:
1. Reconnaissance
2. Vulnerability analysis
3. Exploitation
4. Post-exploitation
5. Reporting and recommendations
6. Validation and retesting
Let’s understand each phase in depth.
Reconnaissance
Reconnaissance (also known as recon) is one of the fundamental phases of a pentest. In this stage,
cybersecurity professionals gather crucial information about the pentesting target, whether it’s a network,
web application, infrastructure, organization, or any other system being evaluated. The main objective
of reconnaissance is to gain a thorough and complete understanding of the target environment to
effectively plan and execute pentesting and discover potential vulnerabilities and weaknesses.
The following are some of the key activities associated with the reconnaissance phase of pentesting:
• Passive information collection: In this stage, information is collected without interacting
directly with the target. This may include searching for information from public sources, such
as social networks, websites, domain records, DNS records, and any other information that is
readily available online. The idea is to create an initial profile of the target.
• Network and port scanning: Once passive information has been collected, a scan of the target
network can be performed to identify active systems and open ports. Tools such as Nmap are
commonly used for this task.
• Service enumeration: After identifying open ports, a service enumeration is performed to
identify which services are running on those ports. This helps us understand the infrastructure
and technologies used by the target.
• Enumeration of users and resources: This stage seeks to identify users, groups, and shared
resources and attempts to map the directory structure and permissions on systems and
applications. This can help us find possible entry points and targets.
Phases of a pentest 85
• Vulnerability scanning: Vulnerability scanning tools and techniques are used to identify
potential weaknesses in systems and applications. This includes looking for missing patches,
misconfigurations, and known vulnerabilities. Some outstanding tools in this field are Acunetix
(https://www.acunetix.com/) and Nessus (https://es-la.tenable.com/
products/nessus).
• Architecture analysis: The network and application architecture is analyzed to identify
potential entry points, privileged access paths, and areas of greatest risk. This helps us plan
the pentesting approach.
• Collecting additional information: As the reconnaissance phase progresses, additional
information continues to be collected as new leads and opportunities arise. This may include
searching for sensitive documents, weak credentials, or information that reveals the internal
structure of the organization.
It is important to emphasize that reconnaissance must be carried out ethically and within the legal and
contractual limits agreed with the client. The objective is to identify vulnerabilities and weaknesses
without causing unnecessary damage or disruption to the client’s environment.
Once the reconnaissance phase is completed, the results are used to plan and execute subsequent
stages of pentesting, such as vulnerability exploitation and reporting results.
Vulnerability analysis
Vulnerability analysis is a critical process in the field of cybersecurity that involves identifying,
assessing, and classifying weaknesses or vulnerabilities present in systems, networks, applications, and
other information technology components. The primary goal of vulnerability analysis is to understand
potential security threats and help organizations take proactive steps to mitigate or eliminate those
vulnerabilities before they can be exploited by attackers.
The key aspects of vulnerability analysis are as follows:
• Identifying assets and systems: Before conducting any vulnerability analysis, it is important to
identify and list all assets and systems to be assessed. This includes servers, workstations, network
devices, web applications, databases, and other components of the information technology
infrastructure. We covered this when we looked at the reconnaissance phase.
• Vulnerability scanning and assessment: In this stage, vulnerability scanning tools are used
to systematically search for known weaknesses in identified assets and systems. These tools
examine the configuration and software for known vulnerabilities and issue detailed reports
on the findings.
• Manual scanning: In addition to automated scanning, manual scanning is essential to detect
vulnerabilities that automated tools may miss. Security analysts can review configurations, source
code, logs, and other environment-specific aspects to identify unique or custom weaknesses.
86 Methodologies for Security Testing
• Risk assessment: The risk associated with each identified vulnerability is assessed. This involves
considering the value of the affected assets, the probability of a successful attack, and the
potential impact on the confidentiality, integrity, and availability of information and systems.
It is important to note that vulnerability scanning is an ongoing process in the cybersecurity field.
Threats and vulnerabilities evolve, so organizations must conduct vulnerability scanning regularly
to keep their security posture up to date. In addition, it is crucial to conduct vulnerability scanning
ethically and within applicable legal and regulatory boundaries.
Exploitation
The exploitation phase is a fundamental part of pentesting and represents one of the most critical steps
in the process of assessing the security of a system or network. In this phase, cybersecurity professionals
attempt to exploit previously identified vulnerabilities in the target system or network in a controlled
and ethical manner. The goal is to demonstrate that a real attacker could successfully exploit these
vulnerabilities and gain unauthorized access or perform malicious actions within the target system.
Here is a description of the key activities that take place during the exploitation phase of a pentest:
• Target selection: Before starting the exploitation phase, the specific targets to be attacked are
selected. These targets can be systems, applications, databases, servers, or other IT infrastructure
components that have previously identified vulnerabilities.
• Exploit development: Pentesters can develop or use exploits, which are programs or scripts
that are designed to take advantage of specific vulnerabilities found in systems. These exploits
can exploit weaknesses such as security flaws, injection vulnerabilities, authentication problems,
or misconfigurations.
• Control and access: If the exploitation is successful, pentesters can gain access to sensitive
systems or data. This access is done under strict control and with the customer’s permission.
The objective is to demonstrate the potential impact of a real attack if the vulnerability is
not corrected.
• Access maintenance (persistence): In some cases, pentesters may attempt to maintain access
to a compromised system even after they have been detected. This is known as persistence
and simulates the tactics that are used by real attackers to maintain their presence on a
compromised system.
Important note
In other types of pentesting, the persistence phase is included in the post-exploitation phase
instead of in the exploitation phase. Both are valid; it depends on the criteria of the bug hunter.
Phases of a pentest 87
The exploitation phase is crucial to demonstrate the real risk posed by the identified vulnerabilities
and to provide a more complete view of the security of the target environment. However, it must be
carried out with caution and always with the consent and supervision of the customer to ensure that
it does not cause damage or unwanted disruption to systems.
Let’s look at an example of persistence. Suppose you’re interested in creating a simple Python script that
can run on a target system every time it is started. The goal is for the script to run in the background
without the user noticing it. Here is a basic example of a Python script that could accomplish this:
import os
import shutil
import sys
# Path of the directory where the persistence script will be copied to
persistence_dir = os.environ['APPDATA'] + '\\Microsoft\Windows\Start
Menu\Programs\Startup'
# persistence file name (change as needed)
file_filename = 'persistence.py'
# We check if the script is already in the persistence location
if not os.path.exists(persistence_dir + filename):
try:
# Copy this script to the persistence directory.
shutil.copyfile(sys.argv[0], persistence_dir + filename)
print('Script successfully copied to the persistence
location.')
except Exception as e:
print('Error copying persistence script:', str(e))
else:
print('Persistence script already exists in the start location.')
# Here you can add any additional code you wish to run in the
background.
# For this example, we're simply going to make the script wait and do
nothing.
try:
while True:
pass
except KeyboardInterrupt:
print('Script stopped by user.')
88 Methodologies for Security Testing
Post-exploitation
The post-exploitation phase is an important stage in pentesting and follows the exploitation phase. In
this phase, cybersecurity professionals seek to maintain access and control over compromised systems
after exploiting a vulnerability. The main goal of post-exploitation is to simulate the tactics that are
used by real attackers once they have gained access to a system and continue to assess the security of
the network and systems from this vantage point.
The key activities and concepts associated with the post-exploitation phase of a pentest are as follows:
• Privilege escalation: Pentesters may attempt to elevate their privileges on the compromised
system to gain access to more critical resources and data. This may involve exploiting additional
vulnerabilities or using privilege escalation techniques.
• Exploration and lateral expansion: Once a level of access has been achieved, pentesters can
explore the internal network for other interesting systems or resources. Lateral expansion
involves moving through the network to identify and compromise other targets.
• Collecting sensitive information: During post-exploitation, valuable information may be
collected, such as confidential data, additional credentials, important documents, or any other
information that may be relevant to the customer or reveal the organization’s vulnerability.
• Data exfiltration (if part of the scope): In certain cases, as part of the agreed scope, pentesters
may attempt to exfiltrate confidential data to demonstrate the possibility of a data leak. This is
done in a controlled and ethical manner, and the client is informed immediately.
The post-exploitation phase is critical to assess an organization’s resilience to persistent threats and
to demonstrate how a real attacker might operate after having compromised a system. As with all
phases of pentesting, it is conducted in a controlled and ethical manner, and all actions that are taken
are reported to the customer.
Report and recommendations
The report and recommendations phase is the final and most essential stage of pentesting. In this
phase, cybersecurity professionals summarize and document all findings, results, and observations
derived from the pentesting process. The main objective is to provide the client with a clear and
complete picture of their organization’s security posture, as well as specific recommendations for
improving their cybersecurity. Chapter 9 will deal with how to prepare such a report.
The key elements of the report and recommendations phase of a pentest are as follows:
• Executive summary
• Methodology
• Description of findings
Guidance and recommendations based on my experience 89
• Evidence of exploitation
• Ranking and prioritization
• Mitigation recommendations
• Conclusions
• Annexes
The report and recommendations phase is a critical outcome of pentesting as it provides the organization
with concrete guidance to strengthen its cybersecurity and address identified vulnerabilities and
weaknesses. The report must be written clearly and accurately so that it is useful to senior management
and the organization’s security team.
Validation and retesting
The validation and retesting phase is an important part of a continuous pentesting program and
represents an iterative cycle in improving an organization’s security. It is often conducted after the
completion of an initial pentest, but it can also be part of an ongoing cybersecurity strategy. This phase
focuses on ensuring that the mitigation and remediation measures that have been implemented in
response to previous tests are effective and that no new vulnerabilities have been introduced during
the remediation process.
Here are the key aspects of the validation and retesting phase:
• Validating fixes: After receiving the results report of a pentest, the organization takes action
to address the identified vulnerabilities and follows the recommendations provided. In this
phase, it is verified whether the implemented fixes are effective and have adequately mitigated
the vulnerabilities.
• Retesting: To ensure that the fixes have been successful and have not introduced new vulnerabilities,
pentesting is repeated in the same environment. This involves re-evaluating systems and
applications to verify whether previously identified vulnerabilities have been eliminated or
adequately mitigated.
• Updated results report: A new results report is generated that describes the findings of the
retesting, including any persistent or new vulnerabilities, as well as the effectiveness of the
implemented fixes.
Now that we’ve explored the various phases of pentesting, we will discuss guidance and recommendations
based on my experience.
Guidance and recommendations based on my experience
In this section, I will provide some guidance and recommendations regarding pentesting that I have
gathered from my experience.
90 Methodologies for Security Testing
Note-taking
Always, always, always take notes; it’s a great habit, so get used to it.
When you are looking for vulnerabilities, while in the reconnaissance phase, you will discover a lot
of things, a lot of information (some important, some not), so you have to know how to write down
only what is necessary and discard what isn’t. By doing this, you will work in a more orderly and
non-chaotic way. This will be reflected in the quality of your work and the report to be delivered.
How should you take notes? Well, this is a bit personal; everyone has a way of taking notes. Some
people like to take digital notes, while others take notes in physical notebooks.
I prefer to take digital notes; for this, I use Notepad, a text and source code editor:
Figure 6.2 – Notepad
Something more sophisticated would be CherryTree since you can take notes with rich text, as well
as include screenshots and utilize other advanced functions:
Figure 6.3 – CherryTree
CherryTree is much more complete and supported by the offensive security community compared
to Notepad.
Guidance and recommendations based on my experience 91
JavaScript files also exist
Often, in a pentest, bug hunters forget or take JavaScript files into account. They focus more on looking
at the Top 10 of the OWASP guide. I’m not saying that this is bad – this is a good practice since the
guide covers the most common vulnerabilities – but everyone forgets to look at the .js files, which
store client-side code.
This file can sometimes contain a lot of interesting information, although the developer can obfuscate
their JavaScript code, which makes it unreadable. However, most types of obfuscation can be reversed.
Let’s see how.
We can search the source code for the assets we wish to analyze. These can be in subdomains, parameters,
hidden functions, and especially in the comments left behind by developers.
Whenever we find these types of files, they are usually unreadable. To turn them into readable code,
we can use Beautifier (https://beautifier.io/).
Clearer code is easier to understand, and we can also search for information by using keywords such
as key, API, URL, send, POST, and GET.
This entire process of searching for .js files can be automated and make our work easier. The following
are a series of tools that do this job:
• GetJS: https://github.com/003random/getJS
• URL Extractor: https://github.com/jobertabma/relative-url-extractor
• GoLinkFinder: https://github.com/0xsha/GoLinkFinder
Sometimes, Beautifier is not enough for us and the code doesn’t look pretty. For this, we have the
de4js tool (https://lelinhtinh.github.io/de4js/), which makes code look better to
the human eye.
Analyzing the API
Look for the API and check if the site you wish to analyze offers information about its API. Sometimes,
they will provide documentation because it is used for public purposes. If you can’t find public
information about your API, you can consider searching for it on your web browser and performing
Google hacking to check if something of value has been indexed. For example, you could use the
search term: site:example.com inurl:api.This is an example of Google hacking, also
called hacking with search engines. It involves taking advantage of the information provided by search
engines, sometimes due to the ignorance of website owners.
92 Methodologies for Security Testing
File upload, winning horse
Uploading files will always be a functionality where, on many occasions, we can find some vulnerability.
For example, the possibility of uploading malicious files, such as the innocuous EICAR virus, is done
to demonstrate that it’s possible to upload code that is interpreted as malicious without the system
preventing it.
Another example would be uploading a very large file – something bigger than what the system allows
– to impersonate a legitimate login and trick users so that you can steal their credentials or upload a
web shell or reverse shell.
In short, try to upload files that are not allowed by the system.
Summary
In this chapter, we discussed the different methodologies for pentesting. We explored the general phases
of a pentest that will help us search for vulnerabilities in the bug bounty world. I also provided some
tips based on my experience in this area. At this point, you will be able to choose the methodology
that best suits your needs, and you will also know how to conduct the different phases of a pentest.
In the next chapter, you will learn about the tools and resources needed to be able to work in the bug
hunting world.
