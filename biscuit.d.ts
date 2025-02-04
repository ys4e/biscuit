declare global {
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

    /** Represents `matcher.rs#Cache` */
    export interface Cache {
        /**
         * This is an array of known packet names.
         * This is not definitive, and is used only for quick reference.
         */
        known_names: string[];

        /**
         * This is an array of known packet IDs.
         * This is not definitive, and is used only for quick reference.
         */
        known_ids: number[];

        /**
         * This maps packet IDs to their guessed name.
         */
        id_map: Map<number, string>;
    }
    
    /** Represents `matcher.rs#Packet` */
    export interface SerializedMessage {
        inner: Map<number, MessageValue>;
    }
    
    /** Represents a `message.rs#Value` */
    export type MessageValue = number | string | ArrayBuffer | SerializedMessage;
}

export {};

// This is done so we can declare global types.