declare interface IStatus {
  signed: boolean;
  message: string;
  subject?: string;
}

export function verifySignatureByPublishName(
  filePath: string,
  publisherName: string[]
): IStatus;
