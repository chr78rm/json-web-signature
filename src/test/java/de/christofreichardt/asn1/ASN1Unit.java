package de.christofreichardt.asn1;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.stream.Stream;
import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ASN1Unit implements Traceable, WithAssertions {

    @BeforeAll
    void init() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "init()");

        try {
        } finally {
            tracer.wayout();
        }
    }

    static byte[] convert(short[] values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }

    record ASN1ES256SignatureTestParam(byte[] encodedSeq, byte[] r, byte[] s) {}

    static Stream<ASN1ES256SignatureTestParam> encoded_ASN1_ES256_SignatureStream() {
        short[][] encodedASN1IntSequences = {
                {
                        0x30, 0x45,
                        0x02, 0x20,
                        0x52, 0x35, 0x22, 0x13, 0xdb, 0x3f, 0xe3, 0xe3, 0xe7, 0x53, 0x95, 0x65, 0x49, 0xcb, 0xca, 0xff, 0x05, 0x6b, 0x3b, 0xc8, 0xdc, 0xb5, 0x3b, 0x1e, 0xb7, 0x2d, 0x4d, 0x47, 0xce, 0x9d, 0xe8, 0x40,
                        0x02, 0x21,
                        0x00, 0x96, 0x46, 0xaf, 0x75, 0x4f, 0x0a, 0x81, 0x00, 0x0c, 0x85, 0xfc, 0x84, 0xee, 0xaf, 0x7f, 0xc4, 0x8a, 0x2e, 0xb4, 0x9c, 0x62, 0xff, 0x31, 0x86, 0x37, 0x54, 0x8f, 0x20, 0xb6, 0xc8, 0x77, 0x50
                },
                {
                        0x30, 0x44,
                        0x02, 0x20,
                        0x39, 0x97, 0xa0, 0x83, 0xd7, 0x74, 0xe6, 0xf6, 0x1c, 0x1a, 0xf5, 0x17, 0xa3, 0xd5, 0x18, 0x44, 0x7c, 0x91, 0x2e, 0x89, 0x69, 0xa1, 0x61, 0x5f, 0x70, 0xf8, 0xfe, 0xfe, 0xce, 0xa6, 0x98, 0xf6,
                        0x02, 0x20,
                        0x23, 0xe2, 0x5b, 0x79, 0xaf, 0x15, 0x6b, 0xd7, 0x02, 0x17, 0xfd, 0xb4, 0xe1, 0x3c, 0x7b, 0xdb, 0xe1, 0xe1, 0x6f, 0xd5, 0xc8, 0x39, 0x8f, 0xb3, 0xb4, 0xb7, 0xde, 0xf3, 0xcf, 0xff, 0xe9, 0x22
                },
                {
                        0x30, 0x46,
                        0x02, 0x21,
                        0x00, 0x9c, 0x3d, 0x52, 0x34, 0x62, 0x69, 0xaa, 0x0d, 0xc7, 0x8e, 0x21, 0x47, 0x94, 0xa4, 0xf4, 0x5a, 0x58, 0x2a, 0xb0, 0x0e, 0x1f, 0x2e, 0x6f, 0x53, 0x57, 0xd0, 0x0d, 0x35, 0x6f, 0x65, 0x3d, 0xcf,
                        0x02, 0x21,
                        0x00, 0xb1, 0xc1, 0x78, 0xa9, 0xa8, 0x7a, 0x45, 0x46, 0x0d, 0xf7, 0x3b, 0xbe, 0x7e, 0xe8, 0x29, 0x62, 0x43, 0x85, 0x82, 0xcd, 0x64, 0x1c, 0x59, 0x8b, 0x50, 0x2c, 0x69, 0x82, 0xf2, 0xfa, 0x34, 0x34
                },
        };
        short[][] r = {
                {0x52, 0x35, 0x22, 0x13, 0xdb, 0x3f, 0xe3, 0xe3, 0xe7, 0x53, 0x95, 0x65, 0x49, 0xcb, 0xca, 0xff, 0x05, 0x6b, 0x3b, 0xc8, 0xdc, 0xb5, 0x3b, 0x1e, 0xb7, 0x2d, 0x4d, 0x47, 0xce, 0x9d, 0xe8, 0x40},
                {0x39, 0x97, 0xa0, 0x83, 0xd7, 0x74, 0xe6, 0xf6, 0x1c, 0x1a, 0xf5, 0x17, 0xa3, 0xd5, 0x18, 0x44, 0x7c, 0x91, 0x2e, 0x89, 0x69, 0xa1, 0x61, 0x5f, 0x70, 0xf8, 0xfe, 0xfe, 0xce, 0xa6, 0x98, 0xf6},
                {0x00, 0x9c, 0x3d, 0x52, 0x34, 0x62, 0x69, 0xaa, 0x0d, 0xc7, 0x8e, 0x21, 0x47, 0x94, 0xa4, 0xf4, 0x5a, 0x58, 0x2a, 0xb0, 0x0e, 0x1f, 0x2e, 0x6f, 0x53, 0x57, 0xd0, 0x0d, 0x35, 0x6f, 0x65, 0x3d, 0xcf},
        };
        short[][] s = {
                {0x00, 0x96, 0x46, 0xaf, 0x75, 0x4f, 0x0a, 0x81, 0x00, 0x0c, 0x85, 0xfc, 0x84, 0xee, 0xaf, 0x7f, 0xc4, 0x8a, 0x2e, 0xb4, 0x9c, 0x62, 0xff, 0x31, 0x86, 0x37, 0x54, 0x8f, 0x20, 0xb6, 0xc8, 0x77, 0x50},
                {0x23, 0xe2, 0x5b, 0x79, 0xaf, 0x15, 0x6b, 0xd7, 0x02, 0x17, 0xfd, 0xb4, 0xe1, 0x3c, 0x7b, 0xdb, 0xe1, 0xe1, 0x6f, 0xd5, 0xc8, 0x39, 0x8f, 0xb3, 0xb4, 0xb7, 0xde, 0xf3, 0xcf, 0xff, 0xe9, 0x22},
                {0x00, 0xb1, 0xc1, 0x78, 0xa9, 0xa8, 0x7a, 0x45, 0x46, 0x0d, 0xf7, 0x3b, 0xbe, 0x7e, 0xe8, 0x29, 0x62, 0x43, 0x85, 0x82, 0xcd, 0x64, 0x1c, 0x59, 0x8b, 0x50, 0x2c, 0x69, 0x82, 0xf2, 0xfa, 0x34, 0x34},
        };
        ASN1ES256SignatureTestParam[] params = new ASN1ES256SignatureTestParam[encodedASN1IntSequences.length];
        for (int i=0; i<encodedASN1IntSequences.length; i++) {
            params[i] = new ASN1ES256SignatureTestParam(convert(encodedASN1IntSequences[i]), convert(r[i]), convert(s[i]));
        }
        return Stream.of(params);
    }

    @ParameterizedTest
    @MethodSource("encoded_ASN1_ES256_SignatureStream")
    void decodeSignaturesWithShortFormLength(ASN1ES256SignatureTestParam asn1ES256SignatureTestParam) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "decodeSignaturesWithShortFormLength(byte[] bytes)");

        try {
            tracer.out().printfIndentln("bytes = %s", HexFormat.ofDelimiter(" ").formatHex(asn1ES256SignatureTestParam.encodedSeq()));
            ASN1IntSequence asn1IntSequence = new ASN1IntSequence(asn1ES256SignatureTestParam.encodedSeq());
            tracer.out().printfIndentln("asn1IntSequence = %s", asn1IntSequence);
            ASN1IntSequence.Iterator iter = asn1IntSequence.iterator();
            ASN1Integer r = iter.next();
            assertThat(r.actualBytes()).isEqualTo(asn1ES256SignatureTestParam.r());
            ASN1Integer s = iter.next();
            assertThat(s.actualBytes()).isEqualTo(asn1ES256SignatureTestParam.s());
            assertThat(iter.hasNext()).isFalse();
            assertThatExceptionOfType(NoSuchElementException.class).isThrownBy(() -> iter.next());
        } finally {
            tracer.wayout();
        }
    }

    record ASN1SeqTestParam(ASN1IntSequence asn1IntSequence, ASN1Integer[] asn1Integers) {
        @Override
        public String toString() {
            return "ASN1SeqTestParam[asn1IntSequence = %s, asn1Integers = %s]".formatted(this.asn1IntSequence, Arrays.toString(this.asn1Integers));
        }
    }

    static Stream<ASN1SeqTestParam> asn1IntSequenceStream() {
        AbstractTracer tracer = TracerFactory.getInstance().getCurrentPoolTracer();
        tracer.entry("Stream<ASN1IntSequence>", ASN1Unit.class, "asn1IntSequenceStream()");

        try {
            final int SEQ_COUNT = 25, MAX_INT_LENGTH = 32, MAX_SEQ_LENGTH = 16;
            ASN1SeqTestParam[] asn1SeqTestParams = new ASN1SeqTestParam[SEQ_COUNT];
            Random random = new Random();
            int index = 0;
            do {
                int seqLength = random.nextInt(MAX_SEQ_LENGTH);
                tracer.out().printfIndentln("index = %d, seqLength = %d", index, seqLength);
                int sum = 2;
                ASN1Integer[] asn1Integers = new ASN1Integer[seqLength];
                for (int j=0; j<seqLength; j++) {
                    int length = random.nextInt(MAX_INT_LENGTH);
                    tracer.out().printfIndentln("length = %d", length);
                    byte[] bytes = new byte[length];
                    random.nextBytes(bytes);
                    ASN1Integer asn1Integer = ASN1Integer.fromBytes(bytes);
                    tracer.out().printfIndentln("asn1Integer = %s", asn1Integer);
                    sum += asn1Integer.asn1Length.rawLength();
                    asn1Integers[j] = asn1Integer;
                }
                tracer.out().printfIndentln("sum = %d", sum);
                if (sum < ASN1.SHORT_LENGTH) {
                    asn1SeqTestParams[index] = new ASN1SeqTestParam(ASN1IntSequence.fromASN1Integers(asn1Integers), asn1Integers);
                    tracer.out().printfIndentln("asn1SeqTestParams[%d] = %s", index, asn1SeqTestParams[index]);
                    index++;
                    if (index >= SEQ_COUNT) {
                        break;
                    }
                }
                tracer.out().printfIndentln("------------------------------------");
            } while(true);

            return Stream.of(asn1SeqTestParams);
        } finally {
            tracer.wayout();
        }
    }

    @ParameterizedTest
    @MethodSource("asn1IntSequenceStream")
    void randomShortSequencesWithShortInts(ASN1SeqTestParam asn1SeqTestParam) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "randomShortSequencesWithShortInts(ASN1SeqTestParam asn1SeqTestParam)");

        try {
            tracer.out().printfIndentln("asn1SeqTestParam = %s", asn1SeqTestParam);
            ASN1IntSequence.Iterator iter = asn1SeqTestParam.asn1IntSequence().iterator();
            int index = 0;
            while (iter.hasNext()) {
                ASN1Integer asn1Integer = iter.next();
                tracer.out().printfIndentln("asn1Integer = %s", asn1Integer);
                assertThat(asn1Integer.toString()).isEqualTo(asn1SeqTestParam.asn1Integers()[index++].toString());
            }
        } finally {
            tracer.wayout();
        }
    }

    @AfterAll
    void exit() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("void", this, "exit()");

        try {
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
