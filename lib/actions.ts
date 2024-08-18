"use server";

import { domainFormSchema } from "./schema";
import {
  getCertificateChain,
  getCertificateInfo,
  parseCertificate,
  validateCertificateChain,
} from "./server_utils";

export default async function validateCertificate(data: { url: string }) {
  const parsed = domainFormSchema.safeParse(data);
  // try {
  if (parsed.success) {
    const url = new URL(data.url);
    const domain = url.host;
    const certificateChain = await getCertificateChain(domain);
    const parsedCertificates = await Promise.all(
      certificateChain.map((cert) => parseCertificate(cert))
    );
    const isChainValid = await validateCertificateChain(parsedCertificates);

    const certificates = await Promise.all(
      parsedCertificates.map(async (cert) => await getCertificateInfo(cert))
    );

    return {
      valid: isChainValid,
      certificates,
    };
  } else {
    return { errors: parsed.error.flatten() };
  }
  // } catch (error) {
  //   return { error: (error as Error).message };
  // }
}
