## **Data Exfiltration from PIP'd Employee** 
![image (3)](https://github.com/user-attachments/assets/7e93bed4-6b56-4daa-9dea-7ad6f8306919)


# 🎯 **Use Case**   

## 📚 **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`okvm`) using Microsoft Defender for Endpoint (MDE).  

---

## 📊 **Incident Summary and Findings**  

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
     ```kql
     DeviceFileEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceNetworkEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceProcessEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceFileEvents
     | where DeviceName == "okvm"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```
![Image](https://github.com/user-attachments/assets/26a8ee86-fd1c-4049-b471-10b9b33da660)

     
2. **⚙️ Process Analysis:**  
   - **Observed Behavior:** I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 mintutes after. I discoverd around the same time. apowershellscript silently installed 7zip and then used 7zip to zip up employee data into an archive.
   - **Detection Query (KQL):**  

     ```kql
     let VMName = "okvm";
     let specificTime = datetime(2025-04-03T02:22:08.6263314Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
     ```
![Image](https://github.com/user-attachments/assets/5ebe96ef-c978-4c9a-a447-794f61ada5c4)


   3. **🌐 Network Exfiltration Check:**  
   - **Observed Behavior:** The VM made several SSL (HTTPS) connections to remote IPs and there were multiple DNS resolution requests to external IPs, indicating possible domain lookups or communication with external servers. Some connections were successful, while others were only inspected. The activity pattern suggests the VM is engaging in external communications, but it is unclear if this is routine traffic or suspicious behavior. 

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "okvm";
     let specificTime = datetime(2025-04-03T02:22:08.6263314Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```

     ![Image](https://github.com/user-attachments/assets/763df2a9-c3a8-45eb-addc-7c42c2137a0d)

4. **📝 Response:**  
   - Shared findings with the manager, highlighting automated archive creation and engaging with external communications. The device was isolated, awaiting further instructions. 

---

---

## 🛡️ MITRE ATT&CK Framework TTPs

| 🏹 Tactic        | 🔧 Technique                               | 🆔 ID         | 📖 Description  |
|-----------------|--------------------------------------|-------------|----------------|
| 🔍 Discovery    | System Information Discovery        | T1082       | The system gathered host-level details, including running processes, before performing further actions. |
| 🛠️ Execution    | PowerShell                          | T1059.001   | PowerShell scripts were executed to install 7-Zip silently and perform file compression activities. |
| 📦 Collection   | Archive Collected Data              | T1560.001   | Sensitive data was compressed into `.zip` files using 7-Zip, likely for easier handling or exfiltration. |
| 📡 Command & Control | Encrypted Channel                 | T1573       | Multiple SSL connections to external IPs were detected, possibly indicating covert communications. |
| 🚛 Exfiltration | Exfiltration Over C2 Channel        | T1041       | Network events suggest potential communication with external servers after file archiving. |
| 🕵️‍♂️ Defense Evasion | Indicator Removal on Host         | T1070       | The process list was reviewed before execution, possibly to avoid detection while performing actions. |
                        |  

---

### 🧑‍💻 **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Owen Kerrisk
- **Author Contact**: https://www.linkedin.com/in/owen-kerrisk-b7743085?/
- **Date**: Apr , 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: https://www.linkedin.com/in/joshmadakor/
- **Validation Date**: Apr , 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Apr 2, 2025`  | `Owen Kerrisk`   
