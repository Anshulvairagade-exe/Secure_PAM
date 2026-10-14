// The @novnc/novnc package exports core/rfb.js at runtime; @types/novnc__novnc still describes the old
// "lib/rfb" path. Re-expose the runtime class under the published types.
import RFBRuntime from '@novnc/novnc';
import type RFBType from '@novnc/novnc/lib/rfb';

export const RFB = RFBRuntime as unknown as typeof RFBType;
export type RFBClient = InstanceType<typeof RFBType>;
