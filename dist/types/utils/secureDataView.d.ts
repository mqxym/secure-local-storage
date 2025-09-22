export type SecureDataView<T extends Record<string, unknown>> = T & {
    clear(): void;
};
export declare function makeSecureDataView<T extends Record<string, unknown>>(payloadIn: T): SecureDataView<T>;
