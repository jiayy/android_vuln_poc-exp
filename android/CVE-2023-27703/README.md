# CVE-2023-27703
CVE-2023-27703  An Android version of pikpak version V1.29.2 element debugging interface leakage vulnerability


fix at pikpak 1.30.1



[Suggested description]
The Android version of pikpak v1.29.2 was discovered to contain an information leak via the debug interface.

------------------------------------------

[Additional Information]
Details link:https://drive.google.com/drive/folders/1Szu9pjivVtG93ceECvnoAjeSABVyfDES?usp=sharing

------------------------------------------

[Vulnerability Type]
Incorrect Access Control

------------------------------------------

[Vendor of Product]
https://mypikpak.com/

------------------------------------------

[Affected Product Code Base]
Android version of pikpak - V1.29.2

------------------------------------------

[Affected Component]
An Android version of pikpak version V1.29.2 element debugging interface leakage vulnerability, which can lead to js code execution(XSS) and information leakage

------------------------------------------

[Attack Type]
Local

------------------------------------------

[Impact Information Disclosure]
true

------------------------------------------

[Attack Vectors]
Details link:https://drive.google.com/drive/folders/1Szu9pjivVtG93ceECvnoAjeSABVyfDES?usp=sharing

a bug in the android version of pikpak,is about element debugging interface leakage vulnerability, which can lead to js code execution and information leakage.
The version I am using is:V1.29.2

The trigger point of the vulnerability is at enter the invitation code to redeem premium,Enter an error code at will, and then click the redeem now button continuously,need to continue clicking after prompt too many attempts please try again 24 hours.Then vConsole will pop up at the bottom right of the page.

![image](https://github.com/happy0717/CVE-2023-27703/blob/main/pikpak_repetition.jpg)

I think this problem is caused by entering the wrong code many times,you can see some error messages in the log.

I think the appearance of vConsole is very dangerous,It can lead to user information leakage, network request interface debugging, element code leakage, user information changes, etc.

------------------------------------------

[Reference]
https://drive.google.com/drive/folders/1Szu9pjivVtG93ceECvnoAjeSABVyfDES?usp=sharing

------------------------------------------

[Discoverer]
happy0717
