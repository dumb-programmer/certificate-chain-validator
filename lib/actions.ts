"use server";

import { exec } from "child_process";
import { domainFormSchema } from "./schema";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

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

const getCertificateChain = async (domain: string): Promise<Buffer[]> => {
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

      const derCertificates = await Promise.all(
        certs.map((cert) => convertToDER(cert))
      );

      resolve(derCertificates);
    });
  });
};

const parseCertificate = (cert: Buffer) => {
  const asn1 = asn1js.fromBER(cert);
  return new pkijs.Certificate({ schema: asn1.result });
};

const isValid = (cert: pkijs.Certificate) => {
  const notBefore = new Date(cert.notBefore.value);
  const notAfter = new Date(cert.notAfter.value);
  const today = new Date();

  return notBefore <= today && today <= notAfter;
};

const validateCertificateChain = async (certBuffers: Buffer[]) => {
  // Parse the certificates from buffers
  const certificates = await Promise.all(
    certBuffers.map((cert) => parseCertificate(cert))
  );

  // Iterate over the certificates
  for (let i = 0; i < certificates.length; i++) {
    const currentCert = certificates[i];

    // console.log(
    //   asn1js.fromBER(
    //     currentCert.extensions
    //       ?.filter((ext) => ext.extnID === pkijs.id_AuthorityInfoAccess)[0].to
    //   ).result
    // );

    console.log(
      currentCert.extensions?.filter(
        (ext) => ext.extnID === pkijs.id_AuthorityInfoAccess
      )[0].extnValue
    );

    // Check if each certificate is valid
    if (!isValid(currentCert)) {
      console.log(`Certificate ${i + 1} is not valid.`);
      return false;
    }

    if (i < certificates.length - 1) {
      const issuerCert = certificates[i + 1]; // next

      try {
        const isSignatureValid = await currentCert.verify(issuerCert);

        if (!isSignatureValid) {
          console.log(
            `Certificate ${i + 1} is not correctly signed by its issuer.`
          );
          return false;
        }
      } catch (err) {
        console.error(`Error verifying chain at certificate ${i + 1}: ${err}`);
        return false;
      }
    }
  }

  return true;
};

export default async function validateCertificate(data: { url: string }) {
  const parsed = domainFormSchema.safeParse(data);
  if (parsed.success) {
    const url = new URL(data.url);
    const domain = url.host;
    console.log(domain);
    const certificateChain = await getCertificateChain(domain);
    const isChainValid = await validateCertificateChain(certificateChain);
    console.log("isChainValid", isChainValid);
  } else {
    return { errors: parsed.error.flatten() };
  }
}
