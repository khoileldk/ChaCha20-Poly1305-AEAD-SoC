`timescale 1ns/1ps

// Independent wide-integer reference for several multi-block MAC streams.
module tb_poly1305_arithmetic;
    reg clk = 0;
    always #5 clk = ~clk;
    reg rst = 1;
    reg start = 0;
    reg finalize = 0;
    reg [129:0] m = 0;
    reg [127:0] r = 0;
    reg [127:0] s = 0;
    wire [127:0] mac_tag;
    wire ready;
    integer stream, block, ticks;
    reg [129:0] reference_acc;
    reg [130:0] reference_sum;
    reg [258:0] wide_product;
    reg [127:0] expected_tag;
    localparam [129:0] PRIME = {130{1'b1}} - 130'd4;
    localparam [127:0] CLAMP = 128'h0ffffffc0ffffffc0ffffffc0fffffff;

    poly1305_core dut (clk, rst, start, finalize, m, r, s, mac_tag, ready);

    task await_ready;
        begin
            ticks = 0;
            // The registered multiplier adds one cycle per partial product.
            while (!ready && ticks < 55) begin
                @(negedge clk);
                ticks = ticks + 1;
            end
            if (!ready) $fatal(1, "Poly1305 timeout");
        end
    endtask

    initial begin
        repeat (3) @(negedge clk);
        rst = 0;
        await_ready();
        for (stream=0; stream<9; stream=stream+1) begin
            r = (stream == 8) ? {128{1'b1}} :
                128'hffeeddccbbaa99887766554433221100 ^
                (stream * 128'h123456789abcdef);
            s = 128'h0123456789abcdeffedcba9876543210 + stream;
            reference_acc = 0;
            for (block=0; block<=stream; block=block+1) begin
                m = (stream == 8) ? {2'b01, {128{1'b1}}} :
                    {2'b01, (128'h102030405060708090a0b0c0d0e0f000 +
                     block * 128'h112233445566778899aabbccddeeff01) ^
                     (stream * 128'hfeedfacecafebabedeadbeef13572468)};
                reference_sum = {1'b0, reference_acc} + {1'b0, m};
                wide_product = reference_sum * (r & CLAMP);
                reference_acc = wide_product % PRIME;
                @(negedge clk); start = 1;
                @(negedge clk); start = 0;
                await_ready();
            end
            expected_tag = reference_acc[127:0] + s;
            @(negedge clk); finalize = 1;
            @(negedge clk); finalize = 0;
            await_ready();
            if (mac_tag !== expected_tag)
                $fatal(1, "Poly1305 stream %0d: got %h expected %h",
                       stream, mac_tag, expected_tag);
        end
        // Three legal padded blocks and r=1 sum to p exactly. This checks
        // the final subtraction path that random vectors almost never reach.
        r = 128'd1;
        s = 128'h0123456789abcdeffedcba9876543210;
        reference_acc = 0;
        for (block=0; block<3; block=block+1) begin
            m = (block == 2) ? {2'b01, 128'hfffffffffffffffffffffffffffffffb} :
                               {2'b01, 128'd0};
            reference_sum = {1'b0, reference_acc} + {1'b0, m};
            wide_product = reference_sum * (r & CLAMP);
            reference_acc = wide_product % PRIME;
            @(negedge clk); start = 1;
            @(negedge clk); start = 0;
            await_ready();
        end
        expected_tag = reference_acc[127:0] + s;
        @(negedge clk); finalize = 1;
        @(negedge clk); finalize = 0;
        await_ready();
        if (mac_tag !== expected_tag)
            $fatal(1, "Poly1305 near-prime: got %h expected %h",
                   mac_tag, expected_tag);
        $display("POLY1305_ARITHMETIC_PASS streams=10 blocks=48");
        $finish;
    end
endmodule
