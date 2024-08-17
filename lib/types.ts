interface SubjectOrIssuerInfo {
  type: string;
  value: string;
}

export interface CertificateInfo {
  serialNumber?: string;
  subjectInfo: SubjectOrIssuerInfo[];
  issuerInfo: SubjectOrIssuerInfo[];
}
