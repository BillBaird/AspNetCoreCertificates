using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateManager;
using CertificateManager.Models;

namespace SBCertUtils
{
  public class CreateCertificatesClientServerAuthRsa
  {
    private readonly CreateCertificates _createCertificates;

    public CreateCertificatesClientServerAuthRsa(CreateCertificates createCertificates)
    {
      this._createCertificates = createCertificates;
    }

    public X509Certificate2 NewRootCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      int pathLengthConstraint,
      string dnsName)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.2"),
        new Oid("1.3.6.1.5.5.7.3.1")
      };
      BasicConstraints basicConstraints = new BasicConstraints()
      {
        CertificateAuthority = true,
        HasPathLengthConstraint = true,
        PathLengthConstraint = pathLengthConstraint,
        Critical = true
      };
      SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName()
      {
        DnsName = new List<string>() { dnsName }
      };
      X509KeyUsageFlags x509KeyUsageFlags = X509KeyUsageFlags.KeyCertSign;
      return this._createCertificates.NewRsaSelfSignedCertificate(distinguishedName, basicConstraints, validityPeriod, subjectAlternativeName, enhancedKeyUsages, x509KeyUsageFlags, new RsaConfiguration());
    }

    public X509Certificate2 NewIntermediateChainedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      int pathLengthConstraint,
      string dnsName,
      X509Certificate2 parentCertificateAuthority)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.2"),
        new Oid("1.3.6.1.5.5.7.3.1")
      };
      BasicConstraints basicConstraints = new BasicConstraints()
      {
        CertificateAuthority = true,
        HasPathLengthConstraint = true,
        PathLengthConstraint = pathLengthConstraint,
        Critical = true
      };
      SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName()
      {
        DnsName = new List<string>() { dnsName }
      };
      X509KeyUsageFlags x509KeyUsageFlags = X509KeyUsageFlags.KeyCertSign;
      return this._createCertificates.NewRsaChainedCertificate(distinguishedName, basicConstraints, validityPeriod, subjectAlternativeName, parentCertificateAuthority, enhancedKeyUsages, x509KeyUsageFlags, new RsaConfiguration());
    }

    public X509Certificate2 NewDeviceChainedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName,
      X509Certificate2 parentCertificateAuthority)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.2"),
        new Oid("1.3.6.1.5.5.7.3.1")
      };
      return this.NewDeviceChainedCertificate(distinguishedName, validityPeriod, dnsName, enhancedKeyUsages, parentCertificateAuthority);
    }

    public X509Certificate2 NewDeviceVerificationCertificate(
      string deviceVerification,
      X509Certificate2 parentCertificateAuthority)
    {
      return this.NewDeviceChainedCertificate(new DistinguishedName()
      {
        CommonName = deviceVerification
      }, new ValidityPeriod()
      {
        ValidFrom = DateTimeOffset.UtcNow,
        ValidTo = DateTimeOffset.UtcNow.AddDays(2.0)
      }, "verify", new OidCollection(), parentCertificateAuthority);
    }

    public X509Certificate2 NewClientChainedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName,
      X509Certificate2 parentCertificateAuthority)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.2")
      };
      return this.NewDeviceChainedCertificate(distinguishedName, validityPeriod, dnsName, enhancedKeyUsages, parentCertificateAuthority);
    }

    public X509Certificate2 NewServerChainedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName,
      X509Certificate2 parentCertificateAuthority)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.1")
      };
      return this.NewDeviceChainedCertificate(distinguishedName, validityPeriod, dnsName, enhancedKeyUsages, parentCertificateAuthority);
    }

    public X509Certificate2 NewServerSelfSignedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.1")
      };
      BasicConstraints basicConstraints = new BasicConstraints()
      {
        CertificateAuthority = false,
        HasPathLengthConstraint = false,
        PathLengthConstraint = 0,
        Critical = true
      };
      SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName()
      {
        DnsName = new List<string>() { dnsName }
      };
      X509KeyUsageFlags x509KeyUsageFlags = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature;
      return this._createCertificates.NewECDsaSelfSignedCertificate(distinguishedName, basicConstraints, validityPeriod, subjectAlternativeName, enhancedKeyUsages, x509KeyUsageFlags, new ECDsaConfiguration());
    }

    public X509Certificate2 NewClientSelfSignedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName)
    {
      OidCollection enhancedKeyUsages = new OidCollection()
      {
        new Oid("1.3.6.1.5.5.7.3.2")
      };
      BasicConstraints basicConstraints = new BasicConstraints()
      {
        CertificateAuthority = false,
        HasPathLengthConstraint = false,
        PathLengthConstraint = 0,
        Critical = true
      };
      SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName()
      {
        DnsName = new List<string>() { dnsName }
      };
      X509KeyUsageFlags x509KeyUsageFlags = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature;
      return this._createCertificates.NewECDsaSelfSignedCertificate(distinguishedName, basicConstraints, validityPeriod, subjectAlternativeName, enhancedKeyUsages, x509KeyUsageFlags, new ECDsaConfiguration());
    }

    private X509Certificate2 NewDeviceChainedCertificate(
      DistinguishedName distinguishedName,
      ValidityPeriod validityPeriod,
      string dnsName,
      OidCollection enhancedKeyUsages,
      X509Certificate2 parentCertificateAuthority)
    {
      BasicConstraints basicConstraints = new BasicConstraints()
      {
        CertificateAuthority = false,
        HasPathLengthConstraint = false,
        PathLengthConstraint = 0,
        Critical = true
      };
      SubjectAlternativeName subjectAlternativeName = new SubjectAlternativeName()
      {
        DnsName = new List<string>() { dnsName }
      };
      X509KeyUsageFlags x509KeyUsageFlags = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature;
      return this._createCertificates.NewRsaChainedCertificate(distinguishedName, basicConstraints, validityPeriod, subjectAlternativeName, parentCertificateAuthority, enhancedKeyUsages, x509KeyUsageFlags, new RsaConfiguration());
    }
  }
}