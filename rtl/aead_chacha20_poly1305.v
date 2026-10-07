module aead_chacha20_poly1305 (
    input wire clk,
    input wire rstn,

    // Commands (1-cycle pulse)
    input wire start_keygen,
    input wire start_aad,
    input wire start_encrypt,
    input wire start_decrypt,
    input wire start_finalize,

    // Inputs
    input wire [255:0] key,
    input wire [95:0]  nonce,
    input wire [31:0]  counter_in,
    
    input wire [127:0] poly_data_in, // AAD or Length block
    input wire [6:0]   enc_valid_bytes, // 0 to 64
    input wire [4:0]   aad_valid_bytes, // 0 to 16

    input wire [511:0] plaintext,    // 64-byte block for encryption

    // Outputs
    output reg keygen_done,
    output reg aad_done,
    output reg encrypt_done,
    output reg finalize_done,
    output wire busy,

    output reg [31:0]  counter_out,
    output reg [511:0] ciphertext,
    output wire [127:0] mac_tag
);

    // --- ChaCha20 Core Interface ---
    reg chacha_cs, chacha_we, chacha_start;
    reg [3:0] chacha_addr;
    reg [31:0] chacha_din;
    wire chacha_ready;
    wire [31:0] chacha_dout;
    
    chacha20_core chacha_inst (
        .clk(clk),
        .rst(~rstn),
        .cs(chacha_cs),
        .we(chacha_we),
        .addr(chacha_addr),
        .din(chacha_din),
        .start(chacha_start),
        .ready(chacha_ready),
        .dout(chacha_dout)
    );

    // --- Poly1305 Core Interface ---
    reg poly_start, poly_finalize;
    reg [129:0] poly_m;
    reg [127:0] poly_r;
    reg [127:0] poly_s;
    wire poly_ready;
    
    poly1305_core poly_inst (
        .clk(clk),
        .rst(~rstn),
        .start(poly_start),
        .finalize(poly_finalize),
        .m(poly_m),
        .r(poly_r),
        .s(poly_s),
        .ready(poly_ready),
        .mac_tag(mac_tag)
    );

    // --- FSM States ---
    reg [4:0] state;
    reg [4:0] step_cnt; // 0 to 15 counter for 16 words
    reg is_decrypt_mode;

    // --- Dynamic Padding Logic ---
    function [129:0] pad_block;
        input [127:0] data;
        input [4:0] vbytes; // 1 to 16
        begin
            case (vbytes)
                5'd1:  pad_block = {2'b01, 120'd0, data[7:0]};
                5'd2:  pad_block = {2'b01, 112'd0, data[15:0]};
                5'd3:  pad_block = {2'b01, 104'd0, data[23:0]};
                5'd4:  pad_block = {2'b01, 96'd0,  data[31:0]};
                5'd5:  pad_block = {2'b01, 88'd0,  data[39:0]};
                5'd6:  pad_block = {2'b01, 80'd0,  data[47:0]};
                5'd7:  pad_block = {2'b01, 72'd0,  data[55:0]};
                5'd8:  pad_block = {2'b01, 64'd0,  data[63:0]};
                5'd9:  pad_block = {2'b01, 56'd0,  data[71:0]};
                5'd10: pad_block = {2'b01, 48'd0,  data[79:0]};
                5'd11: pad_block = {2'b01, 40'd0,  data[87:0]};
                5'd12: pad_block = {2'b01, 32'd0,  data[95:0]};
                5'd13: pad_block = {2'b01, 24'd0,  data[103:0]};
                5'd14: pad_block = {2'b01, 16'd0,  data[111:0]};
                5'd15: pad_block = {2'b01, 8'd0,   data[119:0]};
                5'd16: pad_block = {2'b01, data[127:0]};
                default: pad_block = 130'd0;
            endcase
        end
    endfunction

    function [4:0] get_chunk_valid;
        input [6:0] total_valid;
        input [6:0] chunk_offset; // 0, 16, 32, 48
        begin
            if (total_valid <= chunk_offset)
                get_chunk_valid = 0;
            else if (total_valid >= chunk_offset + 16)
                get_chunk_valid = 16;
            else
                get_chunk_valid = total_valid - chunk_offset;
        end
    endfunction

    wire [4:0] chunk0_valid = get_chunk_valid(enc_valid_bytes, 7'd0);
    wire [4:0] chunk1_valid = get_chunk_valid(enc_valid_bytes, 7'd16);
    wire [4:0] chunk2_valid = get_chunk_valid(enc_valid_bytes, 7'd32);
    wire [4:0] chunk3_valid = get_chunk_valid(enc_valid_bytes, 7'd48);
    
    wire [4:0] current_chunk_valid = (step_cnt == 0) ? chunk0_valid :
                                     (step_cnt == 1) ? chunk1_valid :
                                     (step_cnt == 2) ? chunk2_valid : chunk3_valid;
                                     
    wire [511:0] poly_data_chunk = is_decrypt_mode ? plaintext : ciphertext;
    wire [127:0] current_chunk_data = (step_cnt == 0) ? poly_data_chunk[127:0] :
                                      (step_cnt == 1) ? poly_data_chunk[255:128] :
                                      (step_cnt == 2) ? poly_data_chunk[383:256] : poly_data_chunk[511:384];

    // --- FSM ---

    localparam ST_IDLE       = 5'd0;
    assign busy = state != ST_IDLE;
    
    // Keygen
    localparam ST_KG_LOAD    = 5'd1;
    localparam ST_KG_RUN     = 5'd2;
    localparam ST_KG_WAIT    = 5'd3;
    localparam ST_KG_READ    = 5'd4;
    
    // AAD
    localparam ST_AAD_RUN    = 5'd5;
    localparam ST_AAD_WAIT   = 5'd6;
    
    // Encrypt
    localparam ST_ENC_LOAD   = 5'd7;
    localparam ST_ENC_RUN    = 5'd8;
    localparam ST_ENC_WAIT   = 5'd9;
    localparam ST_ENC_READ   = 5'd10;
    localparam ST_ENC_POLY   = 5'd11;
    localparam ST_ENC_POLY_W = 5'd12;
    
    // Finalize
    localparam ST_FIN_RUN    = 5'd13;
    localparam ST_FIN_WAIT   = 5'd14;
    localparam ST_FIN_WAIT2  = 5'd15;

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            state <= ST_IDLE;
            keygen_done <= 0;
            aad_done <= 0;
            encrypt_done <= 0;
            finalize_done <= 0;
            
            chacha_cs <= 0; chacha_we <= 0; chacha_start <= 0; chacha_addr <= 0; chacha_din <= 0;
            poly_start <= 0; poly_finalize <= 0; poly_m <= 0; poly_r <= 0; poly_s <= 0;
            
            step_cnt <= 0;
            is_decrypt_mode <= 0;
            counter_out <= 0;
            ciphertext <= 0;
        end else begin
            case (state)
                ST_IDLE: begin
                    chacha_start <= 0;
                    poly_start <= 0;
                    poly_finalize <= 0;
                    
                    if (start_keygen) begin
                        state <= ST_KG_LOAD;
                        step_cnt <= 0;
                        counter_out <= 0; // Forced to 0 for keygen
                        keygen_done <= 0;
                    end else if (start_aad) begin
                        state <= ST_AAD_RUN;
                        aad_done <= 0;
                    end else if (start_encrypt) begin
                        state <= ST_ENC_LOAD;
                        step_cnt <= 0;
                        is_decrypt_mode <= 0;
                        counter_out <= counter_in; // Load counter from CPU
                        encrypt_done <= 0;
                    end else if (start_decrypt) begin
                        state <= ST_ENC_LOAD;
                        step_cnt <= 0;
                        is_decrypt_mode <= 1;
                        counter_out <= counter_in; // Load counter from CPU
                        encrypt_done <= 0;
                    end else if (start_finalize) begin
                        state <= ST_FIN_RUN;
                        finalize_done <= 0;
                    end
                end

                // ------------------ KEYGEN ------------------
                ST_KG_LOAD: begin
                    chacha_cs <= 1;
                    chacha_we <= 1;
                    chacha_addr <= step_cnt[3:0] + 4'd4;
                    case (step_cnt[3:0])
                        4'd0:  chacha_din <= key[31:0];
                        4'd1:  chacha_din <= key[63:32];
                        4'd2:  chacha_din <= key[95:64];
                        4'd3:  chacha_din <= key[127:96];
                        4'd4:  chacha_din <= key[159:128];
                        4'd5:  chacha_din <= key[191:160];
                        4'd6:  chacha_din <= key[223:192];
                        4'd7:  chacha_din <= key[255:224];
                        4'd8:  chacha_din <= 32'd0; // Counter = 0 for Keygen
                        4'd9:  chacha_din <= nonce[31:0];
                        4'd10: chacha_din <= nonce[63:32];
                        4'd11: chacha_din <= nonce[95:64];
                        default: chacha_din <= 0;
                    endcase
                    if (step_cnt == 5'd11) begin
                        state <= ST_KG_RUN;
                    end else begin
                        step_cnt <= step_cnt + 1'b1;
                    end
                end
                ST_KG_RUN: begin
                    chacha_cs <= 0; chacha_we <= 0;
                    chacha_start <= 1;
                    state <= ST_KG_WAIT;
                    step_cnt <= 1; // Wait 1 cycle for ready to drop
                end
                ST_KG_WAIT: begin
                    chacha_start <= 0;
                    if (step_cnt == 1) begin
                        step_cnt <= 0;
                    end else if (chacha_ready) begin
                        state <= ST_KG_READ;
                        step_cnt <= 0;
                    end
                end
                ST_KG_READ: begin
                    chacha_cs <= 1; chacha_we <= 0;
                    if (step_cnt < 8) chacha_addr <= step_cnt[3:0];
                    if (step_cnt > 1 && step_cnt <= 9) begin
                        // Read previous cycle's data
                        case (step_cnt - 2)
                            5'd0: poly_r[31:0]   <= chacha_dout;
                            5'd1: poly_r[63:32]  <= chacha_dout;
                            5'd2: poly_r[95:64]  <= chacha_dout;
                            5'd3: poly_r[127:96] <= chacha_dout;
                            5'd4: poly_s[31:0]   <= chacha_dout;
                            5'd5: poly_s[63:32]  <= chacha_dout;
                            5'd6: poly_s[95:64]  <= chacha_dout;
                            5'd7: poly_s[127:96] <= chacha_dout;
                        endcase
                    end
                    if (step_cnt == 5'd9) begin
                        chacha_cs <= 0;
                        keygen_done <= 1;
                        state <= ST_IDLE;

                    end else begin
                        step_cnt <= step_cnt + 1'b1;
                    end
                end

                // ------------------ AAD ------------------
                ST_AAD_RUN: begin
                    if (aad_valid_bytes == 0) begin
                        aad_done <= 1;
                        state <= ST_IDLE;
                    end else begin
                        poly_m <= pad_block(poly_data_in, aad_valid_bytes);

                        poly_start <= 1;
                        state <= ST_AAD_WAIT;
                        step_cnt <= 1;
                    end
                end
                ST_AAD_WAIT: begin
                    poly_start <= 0;
                    if (step_cnt == 1) begin
                        step_cnt <= 0;

                    end else if (poly_ready) begin
                        aad_done <= 1;
                        state <= ST_IDLE;
                    end
                end

                // ------------------ ENCRYPT ------------------
                ST_ENC_LOAD: begin
                    chacha_cs <= 1;
                    chacha_we <= 1;
                    chacha_addr <= step_cnt[3:0] + 4'd4;
                    case (step_cnt[3:0])
                        4'd0:  chacha_din <= key[31:0];
                        4'd1:  chacha_din <= key[63:32];
                        4'd2:  chacha_din <= key[95:64];
                        4'd3:  chacha_din <= key[127:96];
                        4'd4:  chacha_din <= key[159:128];
                        4'd5:  chacha_din <= key[191:160];
                        4'd6:  chacha_din <= key[223:192];
                        4'd7:  chacha_din <= key[255:224];
                        4'd8:  chacha_din <= counter_out; // Use actual counter!
                        4'd9:  chacha_din <= nonce[31:0];
                        4'd10: chacha_din <= nonce[63:32];
                        4'd11: chacha_din <= nonce[95:64];
                        default: chacha_din <= 0;
                    endcase
                    if (step_cnt == 5'd11) begin
                        state <= ST_ENC_RUN;
                    end else begin
                        step_cnt <= step_cnt + 1'b1;
                    end
                end
                ST_ENC_RUN: begin
                    chacha_cs <= 0; chacha_we <= 0;
                    chacha_start <= 1;
                    state <= ST_ENC_WAIT;
                    step_cnt <= 1; // Wait 1 cycle for ready to drop
                end
                ST_ENC_WAIT: begin
                    chacha_start <= 0;
                    if (step_cnt == 1) begin
                        step_cnt <= 0;
                    end else if (chacha_ready) begin
                        state <= ST_ENC_READ;
                        step_cnt <= 0;
                    end
                end
                ST_ENC_READ: begin
                    chacha_cs <= 1; chacha_we <= 0;
                    if (step_cnt < 16) chacha_addr <= step_cnt[3:0];
                    if (step_cnt > 1 && step_cnt <= 17) begin
                        // Debug print

                        
                        // Save keystream, immediately XOR with plaintext to get ciphertext
                        case (step_cnt - 2)
                            5'd0:  ciphertext[31:0]   <= plaintext[31:0]   ^ chacha_dout;
                            5'd1:  ciphertext[63:32]  <= plaintext[63:32]  ^ chacha_dout;
                            5'd2:  ciphertext[95:64]  <= plaintext[95:64]  ^ chacha_dout;
                            5'd3:  ciphertext[127:96] <= plaintext[127:96] ^ chacha_dout;
                            5'd4:  ciphertext[159:128]<= plaintext[159:128]^ chacha_dout;
                            5'd5:  ciphertext[191:160]<= plaintext[191:160]^ chacha_dout;
                            5'd6:  ciphertext[223:192]<= plaintext[223:192]^ chacha_dout;
                            5'd7:  ciphertext[255:224]<= plaintext[255:224]^ chacha_dout;
                            5'd8:  ciphertext[287:256]<= plaintext[287:256]^ chacha_dout;
                            5'd9:  ciphertext[319:288]<= plaintext[319:288]^ chacha_dout;
                            5'd10: ciphertext[351:320]<= plaintext[351:320]^ chacha_dout;
                            5'd11: ciphertext[383:352]<= plaintext[383:352]^ chacha_dout;
                            5'd12: ciphertext[415:384]<= plaintext[415:384]^ chacha_dout;
                            5'd13: ciphertext[447:416]<= plaintext[447:416]^ chacha_dout;
                            5'd14: ciphertext[479:448]<= plaintext[479:448]^ chacha_dout;
                            5'd15: ciphertext[511:480]<= plaintext[511:480]^ chacha_dout;
                        endcase
                    end
                    if (step_cnt == 5'd17) begin
                        chacha_cs <= 0;
                        // Time to feed Poly1305 with 4 blocks of 16-byte
                        state <= ST_ENC_POLY;
                        step_cnt <= 0;
                    end else begin
                        step_cnt <= step_cnt + 1'b1;
                    end
                end
                ST_ENC_POLY: begin
                    if (step_cnt < 4) begin
                        if (current_chunk_valid == 0) begin
                            // Skip this chunk entirely (and all subsequent chunks)
                            step_cnt <= step_cnt + 1'b1;
                        end else begin
                            poly_m <= pad_block(current_chunk_data, current_chunk_valid);

                            poly_start <= 1;
                            state <= ST_ENC_POLY_W;
                        end
                    end else begin
                        counter_out <= counter_out + 1'b1;
                        encrypt_done <= 1;
                        state <= ST_IDLE;
                    end
                end
                ST_ENC_POLY_W: begin
                    poly_start <= 0;
                    if (poly_start == 1) begin

                    end else if (poly_ready) begin
                        step_cnt <= step_cnt + 1'b1;
                        state <= ST_ENC_POLY;
                    end
                end

                // ------------------ FINALIZE ------------------
                ST_FIN_RUN: begin
                    poly_m <= pad_block(poly_data_in, 5'd16); // Length block with padding
                    poly_start <= 1; // Start processing length block!
                    state <= ST_FIN_WAIT;
                    step_cnt <= 1;

                end
                ST_FIN_WAIT: begin
                    poly_start <= 0;
                    if (step_cnt == 1) begin
                        step_cnt <= 0;
                    end else if (poly_ready) begin
                        poly_finalize <= 1; // Now ask for the tag
                        state <= ST_FIN_WAIT2;
                        step_cnt <= 1;
                    end
                end
                ST_FIN_WAIT2: begin
                    poly_finalize <= 0;
                    if (step_cnt == 1) begin
                        // Ignore the previous idle ready until the finalize
                        // request has actually been accepted by Poly1305.
                        if (!poly_ready)
                            step_cnt <= 0;
                    end else if (poly_ready) begin
                        finalize_done <= 1;
                        state <= ST_IDLE;
                    end
                end
            endcase
        end
    end

endmodule
