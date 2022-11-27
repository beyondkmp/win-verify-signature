declare interface IStatus {
  signed: boolean,
  message: string
}

export function verifySignatureByPublishName(filePath: string, publisherName: string): IStatus;