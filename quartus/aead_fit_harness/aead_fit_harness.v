// FPGA timing measurement shell only. Not part of the production AEAD RTL.
// It replaces the AEAD's wide top-level ports with a 32-bit load/read port.
module aead_fit_harness (
    input  wire        clk,
    input  wire        rstn,
    input  wire        write_en,
    input  wire [5:0]  addr,
    input  wire [31:0] write_data,
    input  wire        start_keygen,
    input  wire        start_aad,
    input  wire        start_encrypt,
    input  wire        start_decrypt,
    input  wire        start_finalize,
    output reg  [31:0] read_data
);
    reg [255:0] key;
    reg [95:0] nonce;
    reg [31:0] counter_in;
    reg [127:0] poly_data_in;
    reg [6:0] enc_valid_bytes;
    reg [4:0] aad_valid_bytes;
    reg [511:0] plaintext;

    wire keygen_done, aad_done, encrypt_done, finalize_done, busy;
    wire [31:0] counter_out;
    wire [511:0] ciphertext;
    wire [127:0] mac_tag;

    // Each input bit remains independently controllable through writes.
    always @(posedge clk) begin
        if (write_en) begin
            case (addr)
                6'd0: key[31:0] <= write_data;
                6'd1: key[63:32] <= write_data;
                6'd2: key[95:64] <= write_data;
                6'd3: key[127:96] <= write_data;
                6'd4: key[159:128] <= write_data;
                6'd5: key[191:160] <= write_data;
                6'd6: key[223:192] <= write_data;
                6'd7: key[255:224] <= write_data;
                6'd8: nonce[31:0] <= write_data;
                6'd9: nonce[63:32] <= write_data;
                6'd10: nonce[95:64] <= write_data;
                6'd11: counter_in <= write_data;
                6'd12: poly_data_in[31:0] <= write_data;
                6'd13: poly_data_in[63:32] <= write_data;
                6'd14: poly_data_in[95:64] <= write_data;
                6'd15: poly_data_in[127:96] <= write_data;
                6'd16: begin
                    enc_valid_bytes <= write_data[6:0];
                    aad_valid_bytes <= write_data[12:8];
                end
                6'd17: plaintext[31:0] <= write_data;
                6'd18: plaintext[63:32] <= write_data;
                6'd19: plaintext[95:64] <= write_data;
                6'd20: plaintext[127:96] <= write_data;
                6'd21: plaintext[159:128] <= write_data;
                6'd22: plaintext[191:160] <= write_data;
                6'd23: plaintext[223:192] <= write_data;
                6'd24: plaintext[255:224] <= write_data;
                6'd25: plaintext[287:256] <= write_data;
                6'd26: plaintext[319:288] <= write_data;
                6'd27: plaintext[351:320] <= write_data;
                6'd28: plaintext[383:352] <= write_data;
                6'd29: plaintext[415:384] <= write_data;
                6'd30: plaintext[447:416] <= write_data;
                6'd31: plaintext[479:448] <= write_data;
                6'd32: plaintext[511:480] <= write_data;
                default: ;
            endcase
        end
    end

    aead_chacha20_poly1305 u_aead (
        .clk(clk), .rstn(rstn),
        .start_keygen(start_keygen), .start_aad(start_aad),
        .start_encrypt(start_encrypt), .start_decrypt(start_decrypt),
        .start_finalize(start_finalize),
        .key(key), .nonce(nonce), .counter_in(counter_in),
        .poly_data_in(poly_data_in),
        .enc_valid_bytes(enc_valid_bytes),
        .aad_valid_bytes(aad_valid_bytes),
        .plaintext(plaintext),
        .keygen_done(keygen_done), .aad_done(aad_done),
        .encrypt_done(encrypt_done), .finalize_done(finalize_done),
        .busy(busy), .counter_out(counter_out),
        .ciphertext(ciphertext), .mac_tag(mac_tag)
    );

    // Every output bit is readable, so synthesis retains the complete core.
    always @* begin
        case (addr)
            6'd0: read_data = ciphertext[31:0];
            6'd1: read_data = ciphertext[63:32];
            6'd2: read_data = ciphertext[95:64];
            6'd3: read_data = ciphertext[127:96];
            6'd4: read_data = ciphertext[159:128];
            6'd5: read_data = ciphertext[191:160];
            6'd6: read_data = ciphertext[223:192];
            6'd7: read_data = ciphertext[255:224];
            6'd8: read_data = ciphertext[287:256];
            6'd9: read_data = ciphertext[319:288];
            6'd10: read_data = ciphertext[351:320];
            6'd11: read_data = ciphertext[383:352];
            6'd12: read_data = ciphertext[415:384];
            6'd13: read_data = ciphertext[447:416];
            6'd14: read_data = ciphertext[479:448];
            6'd15: read_data = ciphertext[511:480];
            6'd16: read_data = mac_tag[31:0];
            6'd17: read_data = mac_tag[63:32];
            6'd18: read_data = mac_tag[95:64];
            6'd19: read_data = mac_tag[127:96];
            6'd20: read_data = counter_out;
            6'd21: read_data = {27'd0, busy, finalize_done,
                                encrypt_done, aad_done, keygen_done};
            default: read_data = 32'd0;
        endcase
    end
endmodule
