#@IgnoreInspection BashAddShebang
# cd SomeFolderWhereYouWillRun
cd ~
cd Certificates
rm AspNetCoreCertificates -r -f
git clone https://github.com/BillBaird/AspNetCoreCertificates
cd AspNetCoreCertificates
git checkout Simulation
cd src
dotnet publish -p:DefineConstants="NETSTANDARD2_0" -c Debug -o ./Publish
cd Publish
# Actually run it
./Simulation
./CreateChainedCertsConsoleDemo
7. ls
8. openssl x509 -inform der -in localhost_root_l1.cer.cer -noout -text
9. openssl x509 -inform p12 -in localhost_root_l1.pfx -noout -text
<br />    (Note that this will prompt for a "pass phrase", although it does not appear to work)
10. ./CertsCreateDeviceCertificate/bin/Debug/netcoreapp3.1/CertsCreateDeviceCertificate   openssl pkcsF12 -in Intermediate\ 1.pfx
