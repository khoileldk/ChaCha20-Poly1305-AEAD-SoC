// Area-optimised ChaCha20 block core.
//
// One 32-bit adder is shared by all quarter-round and feed-forward steps.
// The 16-word state is held as four rotating 128-bit rows, avoiding the
// large read/write multiplexers produced by variable array indexing.
module chacha20_core (
  input  wire        clk,
  input  wire        rst,
  input  wire        cs,
  input  wire        we,
  input  wire [3:0]  addr,
  input  wire [31:0] din,
  input  wire        start,
  output reg         ready,
  output reg  [31:0] dout
);

localparam ST_IDLE  = 3'd0;
localparam ST_INIT  = 3'd1;
localparam ST_QR    = 3'd3;
localparam ST_PERM  = 3'd5;
localparam ST_ADD   = 3'd6;
localparam ST_DONE  = 3'd7;

reg [2:0] state;
reg [4:0] round_count;
reg [1:0] quarter_count;
reg [1:0] qr_step;
reg [3:0] add_count;

// Configuration words 4..15. Words 0..3 are fixed ChaCha constants.
reg [127:0] init_row1;
reg [127:0] init_row2;
reg [127:0] init_row3;

// {word 3, word 2, word 1, word 0}; the active word is always [31:0].
reg [127:0] state_row0;
reg [127:0] state_row1;
reg [127:0] state_row2;
reg [127:0] state_row3;

reg  [31:0] add_lhs;
reg  [31:0] add_rhs;
wire [31:0] add_result = add_lhs + add_rhs;
wire [31:0] xor_result = (qr_step == 2'd0 || qr_step == 2'd2) ?
                         (state_row3[31:0] ^ add_result) :
                         (state_row1[31:0] ^ add_result);

function [31:0] initial_word;
  input [3:0] word_index;
  begin
    case (word_index)
      4'd0:  initial_word = 32'h61707865;
      4'd1:  initial_word = 32'h3320646e;
      4'd2:  initial_word = 32'h79622d32;
      4'd3:  initial_word = 32'h6b206574;
      4'd4:  initial_word = init_row1[31:0];
      4'd5:  initial_word = init_row1[63:32];
      4'd6:  initial_word = init_row1[95:64];
      4'd7:  initial_word = init_row1[127:96];
      4'd8:  initial_word = init_row2[31:0];
      4'd9:  initial_word = init_row2[63:32];
      4'd10: initial_word = init_row2[95:64];
      4'd11: initial_word = init_row2[127:96];
      4'd12: initial_word = init_row3[31:0];
      4'd13: initial_word = init_row3[63:32];
      4'd14: initial_word = init_row3[95:64];
      default: initial_word = init_row3[127:96];
    endcase
  end
endfunction

function [31:0] output_word;
  input [3:0] word_index;
  begin
    case (word_index)
      4'd0:  output_word = state_row0[31:0];
      4'd1:  output_word = state_row0[63:32];
      4'd2:  output_word = state_row0[95:64];
      4'd3:  output_word = state_row0[127:96];
      4'd4:  output_word = state_row1[31:0];
      4'd5:  output_word = state_row1[63:32];
      4'd6:  output_word = state_row1[95:64];
      4'd7:  output_word = state_row1[127:96];
      4'd8:  output_word = state_row2[31:0];
      4'd9:  output_word = state_row2[63:32];
      4'd10: output_word = state_row2[95:64];
      4'd11: output_word = state_row2[127:96];
      4'd12: output_word = state_row3[31:0];
      4'd13: output_word = state_row3[63:32];
      4'd14: output_word = state_row3[95:64];
      default: output_word = state_row3[127:96];
    endcase
  end
endfunction

always @(*) begin
  add_lhs = 32'd0;
  add_rhs = 32'd0;
  if (state == ST_QR) begin
    if (qr_step == 2'd0 || qr_step == 2'd2) begin
      add_lhs = state_row0[31:0];
      add_rhs = state_row1[31:0];
    end else begin
      add_lhs = state_row2[31:0];
      add_rhs = state_row3[31:0];
    end
  end else if (state == ST_ADD) begin
    case (add_count[3:2])
      2'd0: add_lhs = state_row0[31:0];
      2'd1: add_lhs = state_row1[31:0];
      2'd2: add_lhs = state_row2[31:0];
      default: add_lhs = state_row3[31:0];
    endcase
    add_rhs = initial_word(add_count);
  end
end

always @(posedge clk or posedge rst) begin
  if (rst) begin
    state         <= ST_IDLE;
    ready         <= 1'b0;
    dout          <= 32'd0;
    round_count   <= 5'd0;
    quarter_count <= 2'd0;
    qr_step       <= 2'd0;
    add_count     <= 4'd0;
    init_row1     <= 128'd0;
    init_row2     <= 128'd0;
    init_row3     <= 128'd0;
    state_row0    <= 128'd0;
    state_row1    <= 128'd0;
    state_row2    <= 128'd0;
    state_row3    <= 128'd0;
  end else begin
    // Configuration writes are accepted only while the datapath is idle.
    if ((state == ST_IDLE || state == ST_DONE) && cs && we) begin
      case (addr)
        4'd4:  init_row1[31:0]   <= din;
        4'd5:  init_row1[63:32]  <= din;
        4'd6:  init_row1[95:64]  <= din;
        4'd7:  init_row1[127:96] <= din;
        4'd8:  init_row2[31:0]   <= din;
        4'd9:  init_row2[63:32]  <= din;
        4'd10: init_row2[95:64]  <= din;
        4'd11: init_row2[127:96] <= din;
        4'd12: init_row3[31:0]   <= din;
        4'd13: init_row3[63:32]  <= din;
        4'd14: init_row3[95:64]  <= din;
        4'd15: init_row3[127:96] <= din;
        default: ;
      endcase
    end

    if (cs && !we && (state == ST_DONE || state == ST_IDLE)) begin
      dout <= output_word(addr);

    end else begin
      dout <= 32'd0;

    end


    case (state)
      ST_IDLE: begin
        ready <= 1'b0;
        if (start)
          state <= ST_INIT;
      end

      ST_INIT: begin
        ready         <= 1'b0;
        round_count   <= 5'd0;
        quarter_count <= 2'd0;
        qr_step       <= 2'd0;
        state_row0 <= {32'h6b206574, 32'h79622d32,
                       32'h3320646e, 32'h61707865};
        state_row1 <= init_row1;
        state_row2 <= init_row2;
        state_row3 <= init_row3;
        state <= ST_QR;
      end

      // Operate on the low word of each row. On the fourth step rotate all
      // four rows so the next quarter round sees the next column.
      ST_QR: begin
        case (qr_step)
          2'd0: begin
            state_row0[31:0] <= add_result;
            state_row3[31:0] <= {xor_result[15:0], xor_result[31:16]};
            qr_step <= 2'd1;
          end
          2'd1: begin
            state_row2[31:0] <= add_result;
            state_row1[31:0] <= {xor_result[19:0], xor_result[31:20]};
            qr_step <= 2'd2;
          end
          2'd2: begin
            state_row0[31:0] <= add_result;
            state_row3[31:0] <= {xor_result[23:0], xor_result[31:24]};
            qr_step <= 2'd3;
          end
          default: begin
            state_row0 <= {state_row0[31:0], state_row0[127:32]};
            state_row1 <= {{xor_result[24:0], xor_result[31:25]}, state_row1[127:32]};
            state_row2 <= {add_result, state_row2[127:32]};
            state_row3 <= {state_row3[31:0], state_row3[127:32]};
            qr_step <= 2'd0;
            if (quarter_count != 2'd3) begin
              quarter_count <= quarter_count + 1'b1;
            end else begin
              quarter_count <= 2'd0;
              state <= ST_PERM;
            end
          end
        endcase
      end

      ST_PERM: begin
        if (!round_count[0]) begin
          // Canonical columns -> diagonal columns (row rotations 0/1/2/3).
          state_row1 <= {state_row1[31:0],  state_row1[127:32]};
          state_row2 <= {state_row2[63:0],  state_row2[127:64]};
          state_row3 <= {state_row3[95:0],  state_row3[127:96]};
        end else begin
          // Diagonal representation -> canonical word order.
          state_row1 <= {state_row1[95:0],  state_row1[127:96]};
          state_row2 <= {state_row2[63:0],  state_row2[127:64]};
          state_row3 <= {state_row3[31:0],  state_row3[127:32]};
        end

        if (round_count == 5'd19) begin
          add_count <= 4'd0;
          state <= ST_ADD;
        end else begin
          round_count <= round_count + 1'b1;
          state <= ST_QR;
        end
      end

      // Each selected row rotates once per added word and therefore returns
      // to canonical order after its four feed-forward additions.
      ST_ADD: begin
        case (add_count[3:2])
          2'd0: state_row0 <= {add_result, state_row0[127:32]};
          2'd1: state_row1 <= {add_result, state_row1[127:32]};
          2'd2: state_row2 <= {add_result, state_row2[127:32]};
          default: state_row3 <= {add_result, state_row3[127:32]};
        endcase
        if (add_count == 4'd15)
          state <= ST_DONE;
        else
          add_count <= add_count + 1'b1;
      end

      ST_DONE: begin
        if (start) begin
          ready <= 1'b0;
          state <= ST_INIT;
        end else begin
          ready <= 1'b1;
        end
      end

      default: begin
        ready <= 1'b0;
        state <= ST_IDLE;
      end
    endcase
  end
end

endmodule
