`timescale 1ns/1ps

// RFC 8439 section 2.3.2 block-function vector at the core's word interface.
module tb_chacha20_core_kat;
    reg clk = 0;
    always #5 clk = ~clk;
    reg rst = 1;
    reg cs = 0;
    reg we = 0;
    reg [3:0] addr = 0;
    reg [31:0] din = 0;
    reg start = 0;
    wire ready;
    wire [31:0] dout;
    integer i;
    integer cycles;
    reg [31:0] expected [0:15];

    chacha20_core dut (clk, rst, cs, we, addr, din, start, ready, dout);

    task write_word;
        input [3:0] index;
        input [31:0] value;
        begin
            @(negedge clk); cs = 1; we = 1; addr = index; din = value;
            @(negedge clk); cs = 0; we = 0;
        end
    endtask

    initial begin
        expected[0]=32'he4e7f110; expected[1]=32'h15593bd1;
        expected[2]=32'h1fdd0f50; expected[3]=32'hc47120a3;
        expected[4]=32'hc7f4d1c7; expected[5]=32'h0368c033;
        expected[6]=32'h9aaa2204; expected[7]=32'h4e6cd4c3;
        expected[8]=32'h466482d2; expected[9]=32'h09aa9f07;
        expected[10]=32'h05d7c214; expected[11]=32'ha2028bd9;
        expected[12]=32'hd19c12b5; expected[13]=32'hb94e16de;
        expected[14]=32'he883d0cb; expected[15]=32'h4e3c50a2;

        repeat (3) @(negedge clk);
        rst = 0;
        for (i=0; i<8; i=i+1)
            write_word(i+4, (i*32'h04040404)+32'h03020100);
        write_word(4'd12, 32'd1);
        write_word(4'd13, 32'h09000000);
        write_word(4'd14, 32'h4a000000);
        write_word(4'd15, 32'd0);

        @(negedge clk); start = 1;
        @(negedge clk); start = 0;
        cycles = 0;
        while (!ready && cycles < 600) begin
            @(negedge clk);
            cycles = cycles + 1;
        end
        if (!ready) $fatal(1, "ChaCha20 timeout");
        for (i=0; i<16; i=i+1) begin
            @(negedge clk); cs=1; we=0; addr=i;
            @(negedge clk);
            if (dout !== expected[i])
                $fatal(1, "ChaCha20 word %0d: got %h expected %h", i, dout, expected[i]);
        end
        $display("CHACHA20_KAT_PASS cycles=%0d", cycles);
        $finish;
    end
endmodule
