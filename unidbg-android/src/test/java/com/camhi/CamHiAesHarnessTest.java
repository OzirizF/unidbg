package com.camhi;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import com.github.unidbg.memory.Memory;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;

public class CamHiAesHarnessTest extends AbstractJni {

    private static final File SO = new File("../../../../artifacts/apk_libs/camhi/lib_arm64-v8a_libHiChipAndroid.so");
    private static final File OUT_DIR = new File("../../../../artifacts/diagnostics/unidbg_camhi_login");

    @Test
    public void generateLoginPackets() throws Exception {
        OUT_DIR.mkdirs();

        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hichip.camhi")
                .build()) {
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            VM vm = emulator.createDalvikVM();
            vm.setVerbose(false);
            vm.setJni(this);

            DalvikModule dm = vm.loadLibrary(SO, false);
            try {
                dm.callJNI_OnLoad(emulator);
            } catch (Throwable ignored) {
                // The exported JNI symbols are enough for this harness.
            }

            Module module = dm.getModule();
            System.out.println("Loaded " + module.name + " base=0x" + Long.toHexString(module.base));

            DvmClass doAes = vm.resolveClass("com/hichip/AesCode/DoAes");
            String[] uids = {
                    "PTZB-421434-CLYUJ",
                    "PTZB-421434-LVJGW2N,HRFCSN",
                    "PTZB421434CLYUJ",
            };
            String[][] credentials = {
                    {"admin", "admin"},
                    {"admin", ""},
                    {"admin", "123456"},
            };
            String[] initModes = {"ext", "legacy"};
            int[] segmentLengths = {0x140, 0x156};
            int[] firstSegmentOffsets = {0x0004, 0x0008};

            for (String uid : uids) {
                for (String[] credential : credentials) {
                    for (String initMode : initModes) {
                        for (int segmentLength : segmentLengths) {
                            for (int firstSegmentOffset : firstSegmentOffsets) {
                                runCase(emulator, vm, doAes, uid, credential[0], credential[1],
                                        initMode, segmentLength, firstSegmentOffset);
                            }
                        }
                    }
                }
            }
        }
    }

    private static void runCase(AndroidEmulator emulator, VM vm, DvmClass doAes,
                                String uid, String username, String password, String initMode, int segmentLength,
                                int firstSegmentOffset) throws Exception {
        long handle = doAes.callStaticJniMethodLong(emulator, "P2PInitEDncrypt()J");
        int mutex = doAes.callStaticJniMethodInt(emulator, "InitMutex(J)I", handle);
        IntArray outRand = new IntArray(vm, new int[4]);

        long initRet;
        if ("legacy".equals(initMode)) {
            initRet = doAes.callStaticJniMethodLong(
                    emulator,
                    "P2PInitEDncryptpwd(JLjava/lang/String;Ljava/lang/String;)J",
                    handle,
                    new StringObject(vm, uid),
                    new StringObject(vm, password));
        } else {
            initRet = doAes.callStaticJniMethodLong(
                    emulator,
                    "P2PInitEDncryptpwdExt(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;[I)J",
                    handle,
                    new StringObject(vm, uid),
                    new StringObject(vm, password),
                    new StringObject(vm, username),
                    outRand);
        }

        ByteArray segmentPassword = new ByteArray(vm, new byte[segmentLength]);
        long passRet = doAes.callStaticJniMethodLong(
                emulator,
                "P2PEDncrypt2Ext(JILjava/lang/String;Ljava/lang/String;II[B)J",
                handle,
                0,
                new StringObject(vm, uid),
                new StringObject(vm, password),
                password.length(),
                1,
                segmentPassword);

        ByteArray segmentUsername = new ByteArray(vm, new byte[segmentLength]);
        long userRet = doAes.callStaticJniMethodLong(
                emulator,
                "P2PEDncrypt2Ext(JILjava/lang/String;Ljava/lang/String;II[B)J",
                handle,
                0,
                new StringObject(vm, uid),
                new StringObject(vm, username),
                username.length(),
                0,
                segmentUsername);

        byte[] loginBlock = buildLoginBlock(segmentUsername.getValue(), segmentPassword.getValue(), firstSegmentOffset);
        byte[] packet = buildD0Packet(loginBlock);

        String safePassword = password.isEmpty() ? "empty" : password;
        File out = new File(OUT_DIR, "d0_" + safeUid(uid) + "_" + username + "_" + safePassword
                + "_" + initMode
                + "_len" + Integer.toHexString(segmentLength)
                + "_off" + Integer.toHexString(firstSegmentOffset) + ".bin");
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(packet);
        }

        System.out.println("case uid=" + uid + " user=" + username + " pwd=" + safePassword
                + " initMode=" + initMode
                + " segmentLen=0x" + Integer.toHexString(segmentLength)
                + " firstOffset=0x" + Integer.toHexString(firstSegmentOffset)
                + " handle=0x" + Long.toHexString(handle)
                + " mutex=" + mutex
                + " initRet=0x" + Long.toHexString(initRet)
                + " passRet=0x" + Long.toHexString(passRet)
                + " userRet=0x" + Long.toHexString(userRet)
                + " outRand=" + intsToString(outRand.getValue())
                + " file=" + out.getPath());
    }

    private static byte[] buildLoginBlock(byte[] segmentUsername, byte[] segmentPassword, int firstSegmentOffset) {
        byte[] block = new byte[0x2B0];
        ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN).putInt(0x1000);
        System.arraycopy(segmentUsername, 0, block, firstSegmentOffset, Math.min(segmentUsername.length, 0x0140));
        System.arraycopy(segmentPassword, 0, block, 0x015A, Math.min(segmentPassword.length, 0x0156));
        return block;
    }

    private static byte[] buildD0Packet(byte[] loginBlock) {
        byte[] packet = new byte[4 + 0x02CC];
        packet[0] = (byte) 0xF1;
        packet[1] = (byte) 0xD0;
        packet[2] = 0x02;
        packet[3] = (byte) 0xCC;
        ByteBuffer payload = ByteBuffer.wrap(packet, 4, 0x02CC).order(ByteOrder.LITTLE_ENDIAN);
        payload.putInt(0x000000D1);
        payload.putInt(0x99999999);
        payload.putInt(0x000002B0);
        payload.put(loginBlock);
        return packet;
    }

    private static String intsToString(int[] values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(values[i]);
        }
        return sb.append(']').toString();
    }

    private static String safeUid(String uid) {
        return uid.toLowerCase(Locale.ROOT)
                .replace('-', '_')
                .replace(',', '_')
                .replaceAll("[^a-z0-9_]+", "_");
    }
}
