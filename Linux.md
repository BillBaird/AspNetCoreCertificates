# Running on Linux
1. cd SomeFolderWhereYouWillRun
1. rm AspNetCoreCertificates -r -f
2. git clone https://github.com/BillBaird/AspNetCoreCertificates
3. cd AspNetCoreCertificates
3. git checkout Simulation
3. cd src
4. dotnet publish -p:DefineConstants="NETSTANDARD2_0" -c Debug -o ./Publish
5. cd Publish
6. \# Actually run it <br /> 
    ./CreateChainedCertsConsoleDemo
7. ls
8. openssl x509 -inform der -in localhost_root_l1.cer.cer -noout -text
9. openssl x509 -inform p12 -in localhost_root_l1.pfx -noout -text
<br />    (Note that this will prompt for a "pass phrase", although it does not appear to work)
10. ./CertsCreateDeviceCertificate/bin/Debug/netcoreapp3.1/CertsCreateDeviceCertificate   openssl pkcsF12 -in Intermediate\ 1.pfx
