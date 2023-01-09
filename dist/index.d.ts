declare interface ISignStatus {
    signed: boolean;
    message: string;
    subject?: string;
}
export declare function verifySignatureByPublishName(filePath: string, publishNames: string[]): ISignStatus;
export {};
