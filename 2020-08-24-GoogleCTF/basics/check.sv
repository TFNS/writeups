module check(
    input clk,

    input [6:0] data, // 7 bit input
    output wire open_safe
);

reg [6:0] memory [7:0]; // 8 element array of 7 bit registers
reg [2:0] idx = 0; // 3 bit register, so counting mod 8

wire [55:0] magic = { // 56 bit array, again MSB to LSB concat bo bits
    {memory[0], memory[5]}, // msb to lsb concat, so memory[0][7],...,memory[0][0],memory[1][7],...,memory[1][0]
    {memory[6], memory[2]},
    {memory[4], memory[3]},
    {memory[7], memory[1]}
};

wire [55:0] kittens = { magic[9:0],  magic[41:22], magic[21:10], magic[55:42] };
assign open_safe = kittens == 56'd3008192072309708; // 56 bit decimal number

always_ff @(posedge clk) begin
    memory[idx] <= data;
    idx <= idx + 5; // it's index % 8 so we're filling memory in order 0, 5, 2, 7, 4, 1, 6, 3
end

endmodule

