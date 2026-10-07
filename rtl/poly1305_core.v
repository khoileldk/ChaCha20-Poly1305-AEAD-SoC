// Radix-32 Poly1305 core with one shared 32x32 multiplier.
// Column accumulation uses a 67-bit adder instead of a 259-bit adder/shifter.
module poly1305_core (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,      // Input a new data block
    input  wire         finalize,   // End of data stream signal, requests latching the Tag
    input  wire [129:0] m,          // 16-byte data block with padded 1 bit (130-bit)
    input  wire [127:0] r,          // r key (unclamped)
    input  wire [127:0] s,          // s key
    
    output reg  [127:0] mac_tag,
    output reg          ready       // Flag indicating readiness to receive a new block
);

    // State definitions
    localparam ST_IDLE = 3'd0;
    localparam ST_MUL  = 3'd1;
    localparam ST_RED0 = 3'd2;
    localparam ST_RED1 = 3'd3;
    localparam ST_RED2 = 3'd4;
    localparam ST_RED3 = 3'd5;
    localparam ST_FIN0 = 3'd6;
    localparam ST_FIN1 = 3'd7;
    localparam ST_PREP = 4'd8;
    localparam ST_A_HIGH = 4'd9;
    localparam ST_RED0_HIGH = 4'd10;
    localparam ST_RED1_HIGH = 4'd11;
    localparam ST_FIN2 = 4'd12;

    reg [3:0]   state;
    reg [2:0]   column;
    reg [1:0]   r_index;
    reg [129:0] acc;         // Accumulator
    reg [130:0] A;           // Register holding the value (acc + m)
    reg [258:0] P;           // Completed product columns
    reg [66:0]  column_acc;  // Carry and partial products for one column
    reg [63:0]  partial_mul_reg;
    reg [31:0]  mul_a_operand;
    reg [31:0]  mul_r_operand;
    reg         mul_acc_phase;
    reg [131:0] red_h5;
    reg [131:0] red_partial;
    reg [130:0] red_second;
    reg [127:0] final_acc_reg;
    reg [65:0]  a_high_pre;
    reg         wide_carry;
    reg [64:0]  tag_high_pre;
    reg         tag_carry;

    // 1. Clamping key r using combinational logic
    wire [127:0] r_clamped = r & 128'h0ffffffc0ffffffc0ffffffc0fffffff;

    // Select the next product's operands during the accumulation cycle.
    // This keeps the limb muxes off the DSP multiplication clock path.
    wire [1:0] last_r_index = (column < 3'd3) ? column[1:0] : 2'd3;
    wire last_product_in_column = (r_index == last_r_index);
    wire [2:0] next_column = last_product_in_column ? column + 1'b1 : column;
    wire [1:0] next_r_index = last_product_in_column ?
                              ((column >= 3'd4) ? column[1:0] - 2'd3 : 2'd0) :
                              r_index + 1'b1;
    wire [2:0] next_a_index = next_column - {1'b0, next_r_index};
    reg [31:0] next_a_chunk;
    always @(*) begin
        case(next_a_index)
            3'd0: next_a_chunk = A[31:0];
            3'd1: next_a_chunk = A[63:32];
            3'd2: next_a_chunk = A[95:64];
            3'd3: next_a_chunk = A[127:96];
            3'd4: next_a_chunk = {29'd0, A[130:128]}; // Only top 3 bits
            default: next_a_chunk = 32'd0;
        endcase
    end

    reg [31:0] next_r_chunk;
    always @(*) begin
        case(next_r_index)
            2'd0: next_r_chunk = r_clamped[31:0];
            2'd1: next_r_chunk = r_clamped[63:32];
            2'd2: next_r_chunk = r_clamped[95:64];
            2'd3: next_r_chunk = r_clamped[127:96];
        endcase
    end

    // 3. One multiplier and a narrow adder, reused for all 20 products.
    (* multstyle = "dsp" *)
    wire [63:0] partial_mul = mul_a_operand * mul_r_operand;
    // Register the DSP result before the carry-propagating column addition.
    // The operands and indices stay fixed until the following cycle.
    wire [66:0] column_sum = column_acc + {3'b000, partial_mul_reg};

    // 4. Reduction modulo 2^130-5. Four registered stages keep the wide
    // carry chains off the same clock path.
    wire [129:0] L = P[129:0];
    wire [128:0] H = P[258:130];
    wire [65:0] a_low_sum = {1'b0, acc[64:0]} + {1'b0, m[64:0]};
    wire [65:0] a_high_sum = {1'b0, acc[129:65]} + {1'b0, m[129:65]};
    wire [131:0] h_times4 = {1'b0, H, 2'b00};
    wire [131:0] h_extended = {3'b000, H};
    wire [66:0] red0_low_sum = {1'b0, h_times4[65:0]} +
                               {1'b0, h_extended[65:0]};
    wire [66:0] red1_low_sum = {1'b0, L[65:0]} +
                               {1'b0, red_h5[65:0]};
    wire [64:0] tag_low_sum = {1'b0, final_acc_reg[63:0]} +
                              {1'b0, s[63:0]};
    wire [64:0] tag_high_sum = {1'b0, final_acc_reg[127:64]} +
                               {1'b0, s[127:64]};
    wire [3:0] fold5 = {red_partial[131:130], 2'b00} + red_partial[131:130];
    // The second fold only adds a four-bit value. Break its carry path
    // into 16-bit local increments and parallel group-carry detectors.
    wire [130:0] folded_sum;
    wire [16:0] folded_low = {1'b0, red_partial[15:0]} + {13'd0, fold5};
    wire [7:0] folded_carry;
    assign folded_sum[15:0] = folded_low[15:0];
    assign folded_carry[0] = folded_low[16];

    // The final fold adds either zero or five, with the same short carry
    // structure. Values overflowing bit 129 retain the original truncation.
    wire [129:0] next_acc;
    wire [16:0] corrected_low = {1'b0, red_second[15:0]} +
                                (red_second[130] ? 17'd5 : 17'd0);
    wire [7:0] corrected_carry;
    assign next_acc[15:0] = corrected_low[15:0];
    assign corrected_carry[0] = corrected_low[16];

    genvar chunk;
    generate
        for (chunk = 1; chunk < 8; chunk = chunk + 1) begin: fold_group
            assign folded_sum[chunk*16 +: 16] =
                red_partial[chunk*16 +: 16] + folded_carry[chunk-1];
            assign folded_carry[chunk] = folded_carry[0] &
                (&red_partial[chunk*16+15:16]);
            assign next_acc[chunk*16 +: 16] =
                red_second[chunk*16 +: 16] + corrected_carry[chunk-1];
            assign corrected_carry[chunk] = corrected_carry[0] &
                (&red_second[chunk*16+15:16]);
        end
    endgenerate
    assign folded_sum[130:128] = {1'b0, red_partial[129:128]} + folded_carry[7];
    assign next_acc[129:128] = red_second[129:128] + corrected_carry[7];

    // 5. Finalization circuit
    // p = 2^130 - 5 = {127{1'b1}, 3'b011}. For a 130-bit acc,
    // subtracting p can only produce 0..4; the tag needs only 128 bits.
    wire final_needs_sub = (&acc[129:3]) && (acc[2:0] >= 3'd3);
    wire [2:0] final_low = acc[2:0] - 3'd3;
    wire [127:0] final_acc = final_needs_sub ? {125'd0, final_low} : acc[127:0];

    // Control State Machine
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state   <= ST_IDLE;
            column  <= 3'd0;
            r_index <= 2'd0;
            acc     <= 130'd0;
            A       <= 130'd0;
            P       <= 259'd0;
            column_acc <= 67'd0;
            partial_mul_reg <= 64'd0;
            mul_a_operand <= 32'd0;
            mul_r_operand <= 32'd0;
            mul_acc_phase <= 1'b0;
            red_h5 <= 132'd0;
            red_partial <= 132'd0;
            red_second <= 131'd0;
            final_acc_reg <= 128'd0;
            a_high_pre <= 66'd0;
            wide_carry <= 1'b0;
            tag_high_pre <= 65'd0;
            tag_carry <= 1'b0;
            mac_tag <= 128'd0;
            ready   <= 1'b0;
        end else begin
            case (state)
                ST_IDLE: begin
                    ready <= 1'b1;
                    if (start) begin
                        ready <= 1'b0;
                        // Capture both halves now so m need not remain
                        // stable after the start pulse.
                        A[64:0] <= a_low_sum[64:0];
                        a_high_pre <= a_high_sum;
                        wide_carry <= a_low_sum[65];
                        column <= 3'd0;
                        r_index <= 2'd0;
                        column_acc <= 67'd0;
                        mul_acc_phase <= 1'b0;
                        state <= ST_A_HIGH;
                    end else if (finalize) begin
                        ready <= 1'b0;
                        state <= ST_FIN0;
                    end
                end

                ST_A_HIGH: begin
                    A[130:65] <= a_high_pre + wide_carry;
                    state <= ST_PREP;
                end

                ST_PREP: begin
                    mul_a_operand <= A[31:0];
                    mul_r_operand <= r_clamped[31:0];
                    state <= ST_MUL;
                end

                ST_MUL: begin
                    if (!mul_acc_phase) begin
                        partial_mul_reg <= partial_mul;
                        mul_acc_phase <= 1'b1;
                    end else begin
                        mul_acc_phase <= 1'b0;
                        mul_a_operand <= next_a_chunk;
                        mul_r_operand <= next_r_chunk;
                        if (r_index == last_r_index) begin
                            // The completed low word is final; only its carry
                            // enters the next product column.
                            case (column)
                                3'd0: P[31:0]    <= column_sum[31:0];
                                3'd1: P[63:32]   <= column_sum[31:0];
                                3'd2: P[95:64]   <= column_sum[31:0];
                                3'd3: P[127:96]  <= column_sum[31:0];
                                3'd4: P[159:128] <= column_sum[31:0];
                                3'd5: P[191:160] <= column_sum[31:0];
                                3'd6: P[223:192] <= column_sum[31:0];
                                default: P[258:224] <= column_sum[34:0];
                            endcase
                            column_acc <= {32'd0, column_sum[66:32]};
                            if (column == 3'd7) begin
                                state <= ST_RED0;
                            end else begin
                                column <= column + 1'b1;
                                r_index <= (column >= 3'd4) ?
                                           column[1:0] - 2'd3 : 2'd0;
                            end
                        end else begin
                            column_acc <= column_sum;
                            r_index <= r_index + 1'b1;
                        end
                    end
                end

                ST_RED0: begin
                    red_h5[65:0] <= red0_low_sum[65:0];
                    wide_carry <= red0_low_sum[66];
                    state <= ST_RED0_HIGH;
                end

                ST_RED0_HIGH: begin
                    red_h5[131:66] <= h_times4[131:66] +
                                       h_extended[131:66] + wide_carry;
                    state <= ST_RED1;
                end

                ST_RED1: begin
                    red_partial[65:0] <= red1_low_sum[65:0];
                    wide_carry <= red1_low_sum[66];
                    state <= ST_RED1_HIGH;
                end

                ST_RED1_HIGH: begin
                    red_partial[131:66] <= {2'b00, L[129:66]} +
                                           red_h5[131:66] + wide_carry;
                    state <= ST_RED2;
                end

                ST_RED2: begin
                    red_second <= folded_sum;
                    state <= ST_RED3;
                end

                ST_RED3: begin
                    acc <= next_acc;
                    state <= ST_IDLE;
                end

                ST_FIN0: begin
                    final_acc_reg <= final_acc;
                    state <= ST_FIN1;
                end

                ST_FIN1: begin
                    mac_tag[63:0] <= tag_low_sum[63:0];
                    tag_high_pre <= tag_high_sum;
                    tag_carry <= tag_low_sum[64];
                    state <= ST_FIN2;
                end

                ST_FIN2: begin
                    mac_tag[127:64] <= tag_high_pre[63:0] + tag_carry;
                    ready   <= 1'b1;
                    state   <= ST_IDLE;
                    acc     <= 130'd0; // Clear state to be ready for a new ciphertext stream
                end
                
                default: state <= ST_IDLE;
            endcase
        end
    end
endmodule
