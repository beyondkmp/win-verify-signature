declare interface IStatus {
  signed: boolean,
  message: string
  signObject?: string
}

export function verifySignatureByPublishName(filePath: string, publisherName: string[]): IStatus;