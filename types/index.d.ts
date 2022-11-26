declare interface IStatus {
  signed: boolean,
  message: string
}

export function verifySignatureByPublishName(filePath: string): Promise<IStatus>;