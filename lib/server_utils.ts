"use server";

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { exec } from "child_process";
import { existsSync } from "fs";
import { readFile, unlink, writeFile } from "fs/promises";
import { CertificateInfo } from "./types";

pkijs.setEngine("node", new pkijs.CryptoEngine({ crypto: crypto }));

const convertToDER = (cert: string) =>
  new Promise<Buffer>((resolve, reject) => {
    exec(
      `echo "${cert}" | openssl x509 -outform DER`,
      { encoding: "buffer" },
      (err, stdout, stderr) => {
        if (err) {
          reject(stderr);
        } else {
          resolve(stdout);
        }
      }
    );
  });

function convertCertificateToPEM(certificate: pkijs.Certificate) {
  // Convert the certificate to DER format
  const derCert = certificate.toSchema(true).toBER(false);

  // Convert the DER to base64
  const base64Cert = Buffer.from(derCert).toString("base64");

  // Wrap with PEM headers and format with line breaks
  const pemCert = [
    "-----BEGIN CERTIFICATE-----",
    ...(base64Cert.match(/.{1,64}/g) as RegExpMatchArray),
    "-----END CERTIFICATE-----",
  ].join("\n");

  return pemCert;
}

export const getCertificateChain = async (
  domain: string
): Promise<string[]> => {
  return new Promise((resolve, reject) => {
    const command = `echo | openssl s_client -connect ${domain}:443 -servername ${domain} -showcerts 2>/dev/null`;

    exec(command, { encoding: "utf-8" }, async (err, stdout, stderr) => {
      if (err) {
        reject(stderr);
        return;
      }

      const certs = Array.from(
        stdout.match(
          /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
        ) as RegExpMatchArray
      );

      resolve(certs);
    });
  });
};

export const parseCertificate = async (cert: string) => {
  const asn1 = asn1js.fromBER(await convertToDER(cert));
  if (asn1.offset === -1) {
    throw new Error("Incorrect encoded ASN.1 data");
  }
  return new pkijs.Certificate({ schema: asn1.result });
};

const isValid = (cert: pkijs.Certificate) => {
  const notBefore = new Date(cert.notBefore.value);
  const notAfter = new Date(cert.notAfter.value);
  const today = new Date();

  return notBefore <= today && today <= notAfter;
};

const createOCSPRequest = async (
  issuerFilename: string,
  certFilename: string,
  reqFilename: string
): Promise<0 | -1> =>
  new Promise((resolve, reject) => {
    exec(
      `openssl ocsp -issuer ${issuerFilename} -cert ${certFilename} -reqout ${reqFilename}`,
      (err, stdout, stderr) => {
        if (err) {
          console.log(stderr);
          return reject(-1);
        }
        return resolve(0);
      }
    );
  });

const sendOCSPRequest = async (
  reqFilename: string,
  ocspURL: string,
  respFilename: string
): Promise<0 | -1> =>
  new Promise((resolve, reject) => {
    exec(
      `curl -X POST -H "Content-Type: application/ocsp-request" --data-binary @${reqFilename} ${ocspURL} > ${respFilename}`,
      (err, stdout, stderr) => {
        if (err) {
          console.log(stderr);
          return reject(-1);
        }
        return resolve(0);
      }
    );
  });

const getOCSPURL = (cert: pkijs.Certificate) =>
  cert.extensions
    ?.find((ext) => ext.extnID === pkijs.id_AuthorityInfoAccess)
    ?.parsedValue?.accessDescriptions.find(
      (desc: any) => desc.accessMethod === pkijs.id_ad_ocsp
    )?.accessLocation?.value;

const checkRevocationStatusUsingOCSP = async (
  ocspUrl: string,
  cert: pkijs.Certificate,
  issuerCert: pkijs.Certificate
) => {
  // // Create OCSP request
  // const ocspReq = new pkijs.OCSPRequest();

  // console.log(convertCertificateToPEM(issuerCert));

  // ocspReq.tbsRequest.requestorName = new pkijs.GeneralName({
  //   type: 4,
  //   value: cert.subject,
  // });

  // await ocspReq.createForCertificate(cert, {
  //   hashAlgorithm: "SHA-256",
  //   issuerCertificate: issuerCert,
  // });

  // const nonce = pkijs.getRandomValues(new Uint8Array(10));
  // ocspReq.tbsRequest.requestExtensions = [
  //   new pkijs.Extension({
  //     extnID: "1.3.6.1.5.5.7.48.1.2", // nonce
  //     extnValue: new asn1js.OctetString({ valueHex: nonce.buffer }).toBER(),
  //   }),
  // ];

  // // Encode OCSP request
  // const ocspReqRaw = ocspReq.toSchema(true).toBER();

  // // Send OCSP Request
  // const response = await fetch(ocspUrl, {
  //   method: "POST",
  //   headers: {
  //     "Content-Type": "application/ocsp-request",
  //   },
  //   body: Buffer.from(ocspReqRaw),
  // });

  // if (!response.ok) {
  //   throw new Error(`Failed to fetch OCSP response: ${response.statusText}`);
  // }

  const issuerFilename = `${crypto.randomUUID()}.pem`;
  const certFilename = `${crypto.randomUUID()}.pem`;
  const ocspReqFilename = `${crypto.randomUUID()}.req`;
  const ocspRespFilename = `${crypto.randomUUID()}.resp`;

  const issuerCertPEM = convertCertificateToPEM(issuerCert);
  const certPEM = convertCertificateToPEM(cert);

  await writeFile(`./${issuerFilename}`, issuerCertPEM);
  await writeFile(`./${certFilename}`, certPEM);

  // Create OCSP request using openssl
  await createOCSPRequest(issuerFilename, certFilename, ocspReqFilename);

  // Send OCSP request
  await sendOCSPRequest(ocspReqFilename, ocspUrl, ocspRespFilename);

  const ocspRespRaw = await readFile(`./${ocspRespFilename}`);

  const asnOcspResp = asn1js.fromBER(Buffer.from(ocspRespRaw));
  const ocspResp = new pkijs.OCSPResponse({
    schema: asnOcspResp.result,
  });

  if (!ocspResp.responseBytes) {
    throw new Error(
      'No "ResponseBytes" in the OCSP Response - nothing to verify'
    );
  }

  const asnOcspRespBasic = asn1js.fromBER(
    ocspResp.responseBytes.response.valueBlock.valueHex
  );
  const ocspBasicResp = new pkijs.BasicOCSPResponse({
    schema: asnOcspRespBasic.result,
  });

  const status =
    ocspBasicResp.tbsResponseData.responses[0].certStatus.idBlock.tagNumber;

  const files = [
    issuerFilename,
    certFilename,
    ocspReqFilename,
    ocspRespFilename,
  ];

  await Promise.all(files.map((filename) => unlink(`./${filename}`)));

  if (status === 0) {
    return false;
  }

  return true;
};

const isSelfSigned = (cert: pkijs.Certificate) =>
  cert.subject.isEqual(cert.issuer);

const downloadCRL = (crlUrl: string, crlFilePath: string) =>
  new Promise((resolve, reject) =>
    exec(`curl ${crlUrl} >> ${crlFilePath}`, (err, stdout, stderr) => {
      if (err) {
        reject(stderr);
        return;
      }
      resolve(stdout);
    })
  );

const getCRLURL = (cert: pkijs.Certificate) =>
  cert?.extensions?.find((ext) => ext.extnID === pkijs.id_CRLDistributionPoints)
    ?.parsedValue.distributionPoints[0].distributionPoint[0].value;

const checkRevocationStatusUsingCRL = async (
  crlURL: string,
  cert: pkijs.Certificate
) => {
  console.log(crlURL);

  const crlFilePath = `./crls/${crlURL.split("/").pop()}`;
  const exists = existsSync(crlFilePath);

  if (!exists) {
    await downloadCRL(crlURL, crlFilePath);
  }

  const CRL = Buffer.from(await readFile(crlFilePath));

  const asnCrl = asn1js.fromBER(CRL);
  const crl = new pkijs.CertificateRevocationList({
    schema: asnCrl.result,
  });

  return crl.revokedCertificates?.some(
    (revokedCert) =>
      revokedCert.userCertificate.valueBlock.valueHexView ===
      cert.serialNumber.valueBlock.valueHexView
  );
};

const isRevoked = async (
  cert: pkijs.Certificate,
  issuerCert?: pkijs.Certificate
) => {
  const crlURL = getCRLURL(cert);
  const ocspURL = getOCSPURL(cert);

  if (crlURL) {
    console.log(crlURL);
    return checkRevocationStatusUsingCRL(crlURL, cert);
  }

  if (issuerCert && ocspURL) {
    console.log(ocspURL);
    return checkRevocationStatusUsingOCSP(ocspURL, cert, issuerCert);
  }
};

export const getCertificateInfo = (
  cert: pkijs.Certificate
): CertificateInfo => {
  // Extract Serial Number
  const serialNumber = Buffer.from(cert.serialNumber.valueBlock.valueHexView)
    .toString("hex")
    .toUpperCase()
    .match(/.{1,2}/g)
    ?.join(":");

  const oidMap: Record<string, string> = {
    "2.5.4.3": "commonName",
    "2.5.4.10": "organizationName",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.9": "streetAddress",
  };

  // Extract Subject Info (Common Name, Organization)
  const subjectInfo = cert.subject.typesAndValues.map((attribute) => ({
    type: oidMap[attribute.type],
    value: attribute.value.valueBlock.value,
  }));

  // Extract Issuer Info (Common Name, Organization)
  const issuerInfo = cert.issuer.typesAndValues.map((attribute) => ({
    type: oidMap[attribute.type],
    value: attribute.value.valueBlock.value,
  }));

  return {
    serialNumber,
    subjectInfo,
    issuerInfo,
  };
};

export const validateCertificateChain = async (
  certificates: pkijs.Certificate[]
) => {
  for (let i = 0; i < certificates.length; i++) {
    const currentCert = certificates[i];

    try {
      if (!isValid(currentCert)) {
        console.log(`Certificate ${i + 1} is not valid.`);
        return false;
      }

      if (isSelfSigned(currentCert)) {
        console.log("self-signed");
        return false;
      }

      if (i < certificates.length - 1) {
        const issuerCert = certificates[i + 1]; // next

        if (await isRevoked(currentCert, issuerCert)) {
          console.log(`Certificate ${i + 1} is revoked.`);
          return false;
        }

        try {
          const isSignatureValid = await currentCert.verify(issuerCert);

          if (!isSignatureValid) {
            console.log(
              `Certificate ${i + 1} is not correctly signed by its issuer.`
            );
            return false;
          }
        } catch (err) {
          console.error(
            `Error verifying chain at certificate ${i + 1}: ${err}`
          );
          return false;
        }
      } else {
        // Check the revocation status for the root cert
        if (await isRevoked(currentCert)) {
          console.log(`Certificate ${i + 1} is not revoked.`);
          return false;
        }
      }
    } catch (err) {
      console.log(err);
      return false;
    }
  }

  return true;
};
