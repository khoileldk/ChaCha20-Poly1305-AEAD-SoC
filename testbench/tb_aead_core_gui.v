`timescale 1ns/1ps

// Direct AEAD-core GUI driver. Reads the same vector format as tb_aead_axi,
// but does not instantiate or exercise the AXI wrapper.
module tb_aead_core_gui;
    reg clk = 1'b0;
    reg rstn = 1'b0;
    always #5 clk = ~clk;

    reg start_keygen = 1'b0;
    reg start_aad = 1'b0;
    reg start_encrypt = 1'b0;
    reg start_decrypt = 1'b0;
    reg start_finalize = 1'b0;
    reg [255:0] key = 256'd0;
    reg [95:0] nonce = 96'd0;
    reg [31:0] counter_in = 32'd0;
    reg [127:0] poly_data_in = 128'd0;
    reg [6:0] enc_valid_bytes = 7'd0;
    reg [4:0] aad_valid_bytes = 5'd0;
    reg [511:0] plaintext = 512'd0;
    wire keygen_done, aad_done, encrypt_done, finalize_done, busy;
    wire [31:0] counter_out;
    wire [511:0] ciphertext;
    wire [127:0] mac_tag;

    aead_chacha20_poly1305 dut (
        .clk(clk), .rstn(rstn),
        .start_keygen(start_keygen), .start_aad(start_aad),
        .start_encrypt(start_encrypt), .start_decrypt(start_decrypt),
        .start_finalize(start_finalize),
        .key(key), .nonce(nonce), .counter_in(counter_in),
        .poly_data_in(poly_data_in),
        .enc_valid_bytes(enc_valid_bytes), .aad_valid_bytes(aad_valid_bytes),
        .plaintext(plaintext),
        .keygen_done(keygen_done), .aad_done(aad_done),
        .encrypt_done(encrypt_done), .finalize_done(finalize_done),
        .busy(busy), .counter_out(counter_out),
        .ciphertext(ciphertext), .mac_tag(mac_tag)
    );

    function [31:0] swap32(input [31:0] value);
        begin
            swap32 = {value[7:0], value[15:8], value[23:16], value[31:24]};
        end
    endfunction

    integer file, scan_file;
    integer num_pt_blocks, num_aad_blocks, msg_byte_len, aad_byte_len;
    integer i, j, start_time, end_time;
    reg [31:0] word_value;
    reg [8*512-1:0] vector_path;
    integer decrypt_mode;

    task read_word;
        begin
            scan_file = $fscanf(file, "%x", word_value);
            if (scan_file != 1)
                $fatal(1, "Malformed AEAD vector word");
        end
    endtask

    task pulse_keygen;
        begin
            @(negedge clk); start_keygen = 1'b1;
            @(negedge clk); start_keygen = 1'b0;
            while (!keygen_done) @(negedge clk);
        end
    endtask

    task pulse_aad;
        begin
            @(negedge clk); start_aad = 1'b1;
            @(negedge clk); start_aad = 1'b0;
            while (!aad_done) @(negedge clk);
        end
    endtask

    task pulse_crypt;
        begin
            @(negedge clk);
            if (decrypt_mode) start_decrypt = 1'b1;
            else start_encrypt = 1'b1;
            @(negedge clk);
            start_decrypt = 1'b0;
            start_encrypt = 1'b0;
            while (!encrypt_done) @(negedge clk);
        end
    endtask

    task pulse_finalize;
        begin
            @(negedge clk); start_finalize = 1'b1;
            @(negedge clk); start_finalize = 1'b0;
            while (!finalize_done) @(negedge clk);
        end
    endtask

    always @(posedge clk) begin
        if (rstn && finalize_done && !dut.poly_ready)
            $fatal(1, "finalize_done asserted before Poly1305 tag is ready");
    end

    initial begin
        #10000000;
        $fatal(1, "AEAD core GUI test timed out");
    end

    initial begin
        repeat (3) @(negedge clk);
        rstn = 1'b1;
        if (!$value$plusargs("VECTOR=%s", vector_path))
            vector_path = "aead_test_vector.txt";
        decrypt_mode = $test$plusargs("DECRYPT");
        file = $fopen(vector_path, "r");
        if (file == 0)
            $fatal(1, "Cannot open AEAD vector file: %s", vector_path);

        scan_file = $fscanf(file, "%d", num_pt_blocks);
        if (scan_file != 1) $fatal(1, "Missing plaintext block count");
        scan_file = $fscanf(file, "%d", num_aad_blocks);
        if (scan_file != 1) $fatal(1, "Missing AAD block count");
        scan_file = $fscanf(file, "%d", msg_byte_len);
        if (scan_file != 1) $fatal(1, "Missing message length");
        scan_file = $fscanf(file, "%d", aad_byte_len);
        if (scan_file != 1) $fatal(1, "Missing AAD length");

        for (i = 0; i < 8; i = i + 1) begin
            read_word();
            key[i*32 +: 32] = word_value;
        end
        for (i = 0; i < 3; i = i + 1) begin
            read_word();
            nonce[i*32 +: 32] = word_value;
        end

        $display("[AEAD core] Direct RTL simulation started");
        start_time = $time;
        pulse_keygen();

        for (i = 0; i < num_aad_blocks; i = i + 1) begin
            poly_data_in = 128'd0;
            for (j = 0; j < 4; j = j + 1) begin
                read_word();
                poly_data_in[j*32 +: 32] = word_value;
            end
            aad_valid_bytes = (i == num_aad_blocks - 1 && aad_byte_len % 16 != 0)
                              ? aad_byte_len % 16 : 16;
            pulse_aad();
        end

        $write("Ciphertext: ");
        for (i = 0; i < num_pt_blocks; i = i + 1) begin
            plaintext = 512'd0;
            for (j = 0; j < 16; j = j + 1) begin
                read_word();
                plaintext[j*32 +: 32] = word_value;
            end
            counter_in = i + 1;
            enc_valid_bytes = (i == num_pt_blocks - 1 && msg_byte_len % 64 != 0)
                              ? msg_byte_len % 64 : 64;
            pulse_crypt();
            for (j = 0; j < enc_valid_bytes; j = j + 1)
                $write("%02x", ciphertext[j*8 +: 8]);
        end
        $display("");

        poly_data_in = {32'd0, msg_byte_len[31:0], 32'd0, aad_byte_len[31:0]};
        pulse_finalize();

        $write("MAC: ");
        for (i = 0; i < 4; i = i + 1)
            $write("%08x", swap32(mac_tag[i*32 +: 32]));
        $display("");

        end_time = $time;
        $display("Total Cycles : %0d cycles", (end_time - start_time) / 10);
        $fclose(file);
        $finish;
    end
endmodule
