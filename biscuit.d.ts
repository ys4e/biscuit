declare global {
    /**
     * The global environment variables, provided by the user.
     */
    export const env: Map<string, string>;

    /**
     * The global module object.
     */
    export const module: { exports: any[] };

    /**
     * Imports a module.
     *
     * @param module The path to the module, relative to the current script.
     */
    export function require(module: string): undefined | any;

    /**
     * Logs an info message to the console.
     *
     * @param message The message to log.
     */
    export function info(message: string): void;

    /**
     * Logs a warning message to the console.
     *
     * @param message The message to log. 
     */
    export function warn(message: string): void;

    /**
     * Decodes a Base64-encoded string.
     * This is the standard Base64 encoding.
     *
     * @param encoded The Base64-encoded string.
     */
    export function base64Decode(encoded: string): ArrayBuffer;

    /**
     * RSA decrypts a message.
     *
     * @param privateKey The private key in PKCS#1 PEM format.
     * @param encryptedData The encrypted data in Base64 format.
     */
    export function rsaDecrypt(privateKey: string, encryptedData: string): ArrayBuffer;

    /**
     * Identifies a packet.
     *
     * @param packetName The name of the packet.
     * @param packetId The ID of the packet.
     * @param fieldData The data of an individual field.
     */
    export function identify(
        packetName: string,
        packetId: number,
        fieldData: FieldData
    ): void;

    /**
     * Checks if a packet is known.
     *
     * @param packetId The ID of the packet. This can be the numerical ID or the packet name.
     */
    export function isKnown(packetId: string | number): boolean;

    /** Represents `matcher.rs#MessageField` */
    export interface FieldData {
        /**
         * The name of the field.
         *
         * If this field name is repeated, the other fields will be categorized under a `oneof`.
         */
        field_name: string;

        /**
         * The type of the field.
         */
        field_type: string;

        /**
         * The ID of the field.
         * This must be unique.
         */
        field_id: number;
    }
    
    /** Represents `matcher.rs#Packet` */
    export interface SerializedMessage {
        inner: Map<number, MessageValue>;

        /**
         * Fetches a value from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        get(key: number): MessageValue | undefined;

        /**
         * Returns all keys in the message.
         *
         * Use {@link get} to fetch a value from the message.
         */
        keys(): number[];

        /**
         * Fetches a `VarInt` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        varint(key: number): number | undefined;

        /**
         * Returns all `VarInt` fields in the message.
         */
        allVarInt(): [number, number][];

        /**
         * Fetches a `float` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        float(key: number): number | undefined;

        /**
         * Returns all `float` fields in the message.
         */
        allFloat(): [number, number][];

        /**
         * Fetches a `double` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        double(key: number): number | undefined;

        /**
         * Returns all `double` fields in the message.
         */
        allDouble(): [number, number][];

        /**
         * Fetches a `string` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        string(key: number): string | undefined;

        /**
         * Returns all `string` fields in the message.
         */
        allString(): [number, string][];

        /**
         * Fetches a `bytes` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        bytes(key: number): ArrayBuffer | undefined;

        /**
         * Returns all `bytes` fields in the message.
         */
        allBytes(): [number, ArrayBuffer][];
        
        /**
         * Fetches a `SerializedMessage` field from the message.
         * Returns `None` if the field with the given ID does not exist.
         *
         * @param key The field ID.
         */
        message(key: number): SerializedMessage | undefined;

        /**
         * Returns all `SerializedMessage` fields in the message.
         */
        allMessage(): [number, SerializedMessage][];
    }
    
    /** Represents a `message.rs#Value` */
    export type MessageValue = number | string | ArrayBuffer | SerializedMessage;
}

export {};

// This is done so we can declare global types.