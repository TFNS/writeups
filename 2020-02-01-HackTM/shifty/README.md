# Shifty (misc, 438p, 37 solved)

A rather nice challenge.
We basically get to play [Sixteen-Puzzle game](https://www.chiark.greenend.org.uk/~sgtatham/puzzles/js/sixteen.html)

The goal is to write a solver for the game.
By playing it a bit we can notice that fixing all rows but the last one is pretty trivial.
We can do this following a kind-of insertion-sort approach.
We sort the blocks one-by-one in order.
Putting first is trivial, then putting every next block requires:

- Move the block `X` we want to put in place to be in the column next to target column
- Shift the target column down until the `X` and whatever is in the place we want to fill are next to each other
- Shift the row with `X` by one place, to put `X` in the correct column
- Shift the target column up until `X` in the right place

In case `X` is already in the correct row or column, we shift the column and/or row, before, so we get back to general case.

This allows us to fix all but the last row.

Fixing the last row is some voodoo-magic, but surprisingly it works!
The general idea is as follows:

- We take `X` and pivot it upwards
- We shift the last row until the target position is below `X`
- We put `X` in place by shifting its column downwards
- Now we have in the last row a single block which needs fixing
- We can fix it the same as we did in the first stage -> put it one column away from target, shift column downwards, shift row by 1 and shift column upwards

There is one special case here -> when there is inversion of last 2 blocks.
I didn't find a clear algorithm to fix this, but the approach which worked was:

- Perform the second stage algorithm to replace last block with first one
- If necessary perform whole solving algorithm one more time

Now in the game there were 5 stages with some twists:

1. Simple small game
2. Simple game with large board
3. Simple game with medium board but you can't see the board between moves. Doesn't matter for us since we solve it all at once anyway.
4. Now the controls are switched, eg shifting column `0` might shift `1` instead. We simply wrote a function which sent all possible rows and columns and observed which one actually moved. Then we "translated" the solution with this mapping.
5. The last stage is similar to 4 but this time like in 3 we can't see the board. This means we can't recover the mapping! But the board is small so we can brute-force it. We guess mapping, send the solution, and if the game was not solved, we send the inverted set of movements, to take board back to start position, and try again different mapping. 

Complete solver:

```python
import itertools

from crypto_commons.generic import chunk
from crypto_commons.netcat.netcat_commons import nc, receive_until_match, interactive, send


def parse_inputs(data):
    data = data.strip()
    rows = len(data.split("\n")) - 1
    data = "".join(data.split("\n")[1:])
    letters = [chr(ord('A') + i) for i in range(rows)]
    for letter in letters:
        data = data.replace(letter, "")
    data = data.replace("\n", "").replace("  ", " ").strip()
    for i in range(10):
        data = data.replace("  ", " ").strip()
    data = list(map(int, data.split(" ")))
    return chunk(data, rows)


def shift_row(tiles, which, moves):
    idx = ord(which) - ord('A')
    row = tiles[idx]
    tiles[idx] = row[1:] + [row[0]]
    return tiles, moves + [which]


def shift_column(tiles, which, moves):
    column = [tiles[i][which] for i in range(len(tiles))]
    column = column[1:] + [column[0]]
    for i in range(len(tiles)):
        tiles[i][which] = column[i]
    return tiles, moves + [which]


def print_grid(tiles):
    for x in tiles:
        print(x)
    print()


def find_position(tiles, t):
    for i in range(len(tiles)):
        for j in range(len(tiles)):
            if tiles[i][j] == t:
                return i, j


def find_grid_index(current_tile, grid_size):
    target_row = current_tile / grid_size
    target_col = current_tile % grid_size
    return target_row, target_col


def solve_all_but_last_row(tiles):
    moves = []
    to_do = len(tiles) * (len(tiles) - 1)
    for t in range(to_do):
        target_row, target_col = find_grid_index(t, len(tiles))
        row, col = find_position(tiles, t)
        x, y = target_row - row, target_col - col
        if x == 0:  # we're on the right row we want to be
            for i in range(len(tiles) - 1):
                tiles, moves = shift_column(tiles, col, moves)
            row += 1
            tiles, moves = shift_row(tiles, chr(row + ord('A')), moves)
            tiles, moves = shift_column(tiles, col, moves)
            row, col = find_position(tiles, t)
            x, y = target_row - row, target_col - col
        if y == 0:  # we're on the right column we want to be
            tiles, moves = shift_row(tiles, chr(row + ord('A')), moves)
            row, col = find_position(tiles, t)
            x, y = target_row - row, target_col - col
        for step in range(len(tiles) + x):
            column_move = target_col
            tiles, moves = shift_column(tiles, column_move, moves)
        for step in range(len(tiles) - y):
            tiles, moves = shift_row(tiles, chr(row + ord('A')), moves)
        for step in range(len(tiles) - (x % len(tiles))):
            column_move = target_col
            tiles, moves = shift_column(tiles, column_move, moves)
    return [str(x) for x in moves], tiles


def fix_first(last_row, moves, tiles):
    first_tile = len(tiles) * (len(tiles) - 1)
    for current_position_in_row in range(last_row.index(first_tile)):  # fix first one
        tiles, moves = shift_row(tiles, chr(ord('A') + len(tiles) - 1), moves)
    return moves, tiles


def solve_last_row(tiles, moves):
    row = chr(ord('A') + len(tiles) - 1)
    moves, tiles = fix_first(tiles[-1], moves, tiles)
    for current_position_in_row in range(len(tiles)):
        current_tile = tiles[-1][current_position_in_row]
        expected_tile_at_current_position = current_position_in_row + len(tiles) * (len(tiles) - 1)
        if current_tile != expected_tile_at_current_position:
            pivot = tiles[-1].index(expected_tile_at_current_position)
            for j in range(len(tiles) - 1):
                tiles, moves = shift_column(tiles, pivot, moves)  # pivot what we want to get
            for j in range(len(tiles) + current_position_in_row - pivot):
                tiles, moves = shift_row(tiles, row, moves)  # set to right position
            tiles, moves = shift_column(tiles, pivot, moves)  # put the pivot in place
            tiles, moves = shift_row(tiles, row, moves)
            adder = 1
            if pivot == tiles[-1].index(min(tiles[-1])):
                tiles, moves = shift_row(tiles, row, moves)
                adder += 1
            for j in range(len(tiles) - 1):
                tiles, moves = shift_column(tiles, pivot, moves)
            for j in range(2 * len(tiles) - (len(tiles) + current_position_in_row - pivot + adder)):
                tiles, moves = shift_row(tiles, row, moves)
            tiles, moves = shift_column(tiles, pivot, moves)
            moves, tiles = fix_first(tiles[-1], moves, tiles)
    # fix one last case when there is inversion of last 2 numbers, this sometimes work:
    if tiles[-1][-1] < tiles[-1][-2]:
        pivot = len(tiles) - 2
        current_position_in_row = 0
        for j in range(len(tiles) - 1):
            tiles, moves = shift_column(tiles, pivot, moves)  # pivot what we want to get
        for j in range(len(tiles) + current_position_in_row - pivot):
            tiles, moves = shift_row(tiles, row, moves)  # set to right position
        tiles, moves = shift_column(tiles, pivot, moves)  # put the pivot in place
        tiles, moves = shift_row(tiles, row, moves)
        adder = 1
        if pivot == tiles[-1].index(min(tiles[-1])):
            tiles, moves = shift_row(tiles, row, moves)
            adder += 1
        for j in range(len(tiles) - 1):
            tiles, moves = shift_column(tiles, pivot, moves)
        for j in range(2 * len(tiles) - (len(tiles) + current_position_in_row - pivot + adder)):
            tiles, moves = shift_row(tiles, row, moves)
        tiles, moves = shift_column(tiles, pivot, moves)
        moves, tiles = fix_first(tiles[-1], moves, tiles)
    return [str(x) for x in moves], tiles


def solve(tiles):
    moves = []
    failed = True
    while failed:
        failed = False
        new_moves, tiles = solve_all_but_last_row(tiles)
        moves += new_moves
        moves, tiles = solve_last_row(tiles, moves)
        for i in range(len(tiles)):
            for j in range(len(tiles)):
                if tiles[i][j] != i * len(tiles) + j:
                    failed = True
                    print("RETRY")
                    break
    print_grid(tiles)
    return moves


def map_moves(moves, row_mapping, col_mapping):
    mapped_moves = []
    for move in moves:
        if str(move) in row_mapping:
            mapped_moves.append(str(row_mapping[move]))
        elif str(move) in col_mapping:
            mapped_moves.append(str(col_mapping[move]))
        else:
            mapped_moves.append(str(move))
    return mapped_moves


def detect_moves(s):
    receive_until_match(s, ":")
    row_mapping = {}
    send(s, "0")
    board = receive_until_match(s, "\n\n")
    receive_until_match(s, ":")
    tiles = parse_inputs(board)
    for row in range(len(tiles)):
        send(s, chr(ord('A') + row))
        board = receive_until_match(s, "\n\n")
        receive_until_match(s, ":")
        new_tiles = parse_inputs(board)
        for i in range(len(tiles)):
            if tiles[i] != new_tiles[i]:
                row_mapping[chr(ord('A') + i)] = chr(ord('A') + row)
                break
        tiles = new_tiles
    col_mapping = {}
    for col in range(len(tiles[0])):
        send(s, str(col))
        board = receive_until_match(s, "\n\n")
        receive_until_match(s, ":")
        new_tiles = parse_inputs(board)
        for i in range(len(tiles[0])):
            if tiles[0][i] != new_tiles[0][i]:
                col_mapping[str(i)] = str(col)
                break
        tiles = new_tiles
    return row_mapping, col_mapping


def random_mapping(options):
    for perm in itertools.permutations(options):
        yield {str(options[i]): str(x) for i, x in enumerate(perm)}


def invert(mapped_solution, size):
    inversion = []
    for step in mapped_solution[::-1]:
        inversion += [step for _ in range(size - 1)]
    return inversion


def main():
    port = 60006
    host = "138.68.67.161"
    s = nc(host, port)
    for i in range(3):
        print(receive_until_match(s, "Current board:\n\n"))
        board = receive_until_match(s, "\n\n")
        print(board)
        tiles = parse_inputs(board)
        solution = solve(tiles)
        solution = ",".join(solution).encode("utf-8")
        print('solution', solution)
        send(s, solution)

    print(receive_until_match(s, "Current board:\n\n"))
    board = receive_until_match(s, "\n\n")
    print(board)
    tiles = parse_inputs(board)
    print_grid(tiles)
    row_mapping, column_mapping = detect_moves(s)
    print('mappings', row_mapping, column_mapping)
    send(s, "0")
    board = receive_until_match(s, "\n\n")
    receive_until_match(s, ":")
    tiles = parse_inputs(board)
    solution = map_moves(solve(tiles), row_mapping, column_mapping)
    solution = ",".join(solution).encode("utf-8")
    print('solution', solution)
    send(s, solution)

    print(receive_until_match(s, "Current board:\n\n"))
    board = receive_until_match(s, "\n\n")
    print(receive_until_match(s, "Enter.*: "))
    print(board)
    initial_board_tiles = parse_inputs(board)
    solution = solve(initial_board_tiles[::])
    index = 0
    for col_mapping in random_mapping(range(len(tiles))):
        for row_mapping in random_mapping([chr(ord('A') + i) for i in range(len(tiles))]):
            print(index, 'testing mappings', row_mapping, col_mapping)
            index += 1
            mapped_solution = map_moves(solution, row_mapping, col_mapping)
            solution_payload = ",".join(mapped_solution).encode("utf-8")
            print('solution', solution_payload)
            send(s, solution_payload)
            res = receive_until_match(s, "Enter.*: ", timeout=3, break_on_empty=True)
            print('response: ', res)
            if "Enter" in res:
                print("Failed, reverting")
                inversion = invert(mapped_solution, len(tiles))
                solution_payload = ",".join(inversion).encode("utf-8")
                send(s, solution_payload)
                print('revert response', receive_until_match(s, "Enter.*: "))
            else:
                print("interactive")
                interactive(s)


main()
```

After a moment we get `HackTM{you_sp1n_me_r1ght_r0und_b4by_round_r0und}`
