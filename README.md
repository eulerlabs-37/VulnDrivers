sc create _SERVICE_NAME_ type= kernel binPath= C:\Users\User\source\repos\VulnerableDriver\x64\Debug\VulnerableDriver\VulnerableDriver.sys

sc start _SERVICE_NAME_
sc stop _SERVICE_NAME_

sc config _SERVICE_NAME_ start= auto

sc delete _SERVICE_NAME_