import math
import random
import time
import os
import threading
import iptc

# --- MCTS Node Structure ---
class MCTSNode:
    """ A node in the Monte Carlo Tree Search. """
    def __init__(self, state, player_type, parent=None, move=None):
        self.state = state  # The game state (e.g., {'type': 'network_threat', 'attacker_ip': '...'})
        self.parent = parent
        self.move = move  # The move that led to this state
        self.children = []
        self.wins = 0      # 'wins' for the *defender*
        self.visits = 0
        self.player_type = player_type # 'attacker' or 'defender'
        self.untried_moves = self.get_possible_moves()

    def get_possible_moves(self):
        """ Get all possible moves from this state based on player type. """
        state_type = self.state.get('type')
        if self.player_type == 'attacker':
            if state_type == 'network_threat':
                return get_network_attacker_moves(self.state)
            elif state_type == 'host_anomaly':
                return get_host_attacker_moves(self.state)
        else: # defender
            if state_type == 'network_threat':
                return get_network_defender_moves(self.state)
            elif state_type == 'host_anomaly':
                return get_host_defender_moves(self.state)
        return []

    def ucb_score(self, C=1.41):
        """ Calculates the UCB1 score for this node. """
        if self.visits == 0:
            return float('inf')
        # We want to maximize the *defender's* win rate
        exploitation = self.wins / self.visits
        exploration = C * math.sqrt(math.log(self.parent.visits) / self.visits)
        return exploitation + exploration

    def add_child(self, move, new_state, player_type):
        """ Add a new child node for a move. """
        child = MCTSNode(state=new_state, player_type=player_type, parent=self, move=move)
        self.children.append(child)
        if move in self.untried_moves:
             self.untried_moves.remove(move)
        return child

    def update(self, result):
        """ Update this node's stats from a simulation result. """
        self.visits += 1
        # Result is from defender's perspective (1 = defender win, 0 = draw, -1 = attacker win)
        self.wins += result

# --- "Game Rules" & Simulation Logic ---
# These functions define the "game" Sentinel is playing.

def get_network_attacker_moves(state):
    """ Define potential ATTACKER moves for a network threat. """
    # In a real system, you'd query a threat intel graph or CVE database.
    # For now, we'll use a static list based on the alert.
    moves = [
        f"scan_network_from({state.get('attacker_ip')})",
        f"bruteforce_ssh({state.get('target_host', 'any')})",
        f"exploit_cve(CVE-202X-XXXX, {state.get('target_host', 'any')})",
        "establish_c2_channel",
        "exfiltrate_data"
    ]
    return moves

def get_network_defender_moves(state):
    """ Define potential DEFENDER moves for a network threat. """
    ip = state.get('attacker_ip')
    moves = [
        f"block_ip_temp({ip})", # The action we want
        f"block_ip_perm({ip})",
        f"isolate_host({state.get('target_host', 'any')})",
        "honeypot_redirect",
        "log_all_traffic"
    ]
    return moves

def get_host_attacker_moves(state):
    """ Define potential ATTACKER moves for a host anomaly. """
    proc = state.get('suspicious_process', 'unknown')
    moves = [
        "privilege_escalation",
        f"process_hollowing({proc})",
        "ransomware_encrypt",
        "spawn_reverse_shell",
        "delete_logs"
    ]
    return moves

def get_host_defender_moves(state):
    """ Define potential DEFENDER moves for a host anomaly. """
    proc = state.get('suspicious_process', 'unknown')
    moves = [
        f"kill_process_tree({proc})", # A strong action
        f"pause_process({proc})",
        "snapshot_vm",
        "quarantine_user_account",
        "dump_process_memory"
    ]
    return moves

def apply_move(state, move):
    """ 
    Create a *new* state reflecting the move. 
    This is crucial for the simulation.
    """
    new_state = state.copy()
    new_state['history'] = new_state.get('history', []) + [move]
    
    # Simple logic to simulate state change
    if "block_ip" in move and new_state['type'] == 'network_threat':
        new_state['blocked_ips'] = new_state.get('blocked_ips', []) + [new_state.get('attacker_ip')]
    if "kill_process" in move and new_state['type'] == 'host_anomaly':
        new_state['killed_processes'] = new_state.get('killed_processes', []) + [new_state.get('suspicious_process')]
        
    return new_state

def is_terminal_state(state, max_depth=10):
    """ Check if the "game" is over. """
    if len(state.get('history', [])) > max_depth:
        return True # Game timed out
    
    if state.get('type') == 'network_threat':
        if state.get('attacker_ip') in state.get('blocked_ips', []):
            return True # Attacker is blocked
    
    if state.get('type') == 'host_anomaly':
        if state.get('suspicious_process') in state.get('killed_processes', []):
            return True # Threat is neutralized
    
    # Add an attacker win condition
    if "ransomware_encrypt" in state.get('history', []) or "exfiltrate_data" in state.get('history', []):
        return True # Attacker wins

    return False

def run_simulation(state):
    """
    This is the "rollout" phase. Simulate a random game to the end.
    Returns a score from the DEFENDER's perspective.
    (1 = Defender Win, 0 = Draw, -1 = Attacker Win)
    """
    sim_state = state.copy()
    current_player = 'attacker' # After defender's expansion, it's attacker's turn
    
    for _ in range(10): # Max 10 moves per simulation
        if is_terminal_state(sim_state):
            break
            
        possible_moves = []
        if current_player == 'attacker':
            if sim_state.get('type') == 'network_threat':
                possible_moves = get_network_attacker_moves(sim_state)
            else:
                possible_moves = get_host_attacker_moves(sim_state)
            current_player = 'defender'
        else:
            if sim_state.get('type') == 'network_threat':
                possible_moves = get_network_defender_moves(sim_state)
            else:
                possible_moves = get_host_defender_moves(sim_state)
            current_player = 'attacker'

        if not possible_moves:
            break
            
        move = random.choice(possible_moves)
        sim_state = apply_move(sim_state, move)

    # Now, score the final state
    if "ransomware_encrypt" in sim_state.get('history', []) or "exfiltrate_data" in sim_state.get('history', []):
        return -1 # Attacker Win
        
    if state.get('type') == 'network_threat' and state.get('attacker_ip') in sim_state.get('blocked_ips', []):
        return 1 # Defender Win
        
    if state.get('type') == 'host_anomaly' and state.get('suspicious_process') in sim_state.get('killed_processes', []):
        return 1 # Defender Win

    return 0 # Draw / Timeout

# --- Main MCTS Orchestrator ---

def run_mcts(initial_state, iterations=1000):
    """
    Runs the MCTS algorithm from a given state.
    """
    # We are the defender, so we start with the defender to play
    root = MCTSNode(state=initial_state, player_type='defender')

    for _ in range(iterations):
        node = root
        current_state = initial_state.copy()
        
        # 1. Selection
        while node.untried_moves == [] and node.children != []:
            node = max(node.children, key=lambda n: n.ucb_score())
            current_state = apply_move(current_state, node.move)

        # 2. Expansion
        if node.untried_moves != []:
            move = random.choice(node.untried_moves)
            next_player = 'attacker' if node.player_type == 'defender' else 'defender'
            new_state = apply_move(current_state, move)
            node = node.add_child(move, new_state, next_player)

        # 3. Simulation
        # Run simulation from the newly expanded node
        result = run_simulation(node.state)

        # 4. Backpropagation
        while node is not None:
            # Result is already from defender's perspective
            node.update(result)
            node = node.parent

    # After all iterations, choose the best defensive move (most visited)
    if not root.children:
        return "no_action_determined", []
        
    best_move_node = max(root.children, key=lambda n: n.visits)
    
    # Get the "Top 5 Attacker Moves" by analyzing *their* hypothetical responses
    # These are the children of our *best* defensive move
    attacker_responses = []
    if best_move_node.children:
         attacker_responses = sorted(best_move_node.children, key=lambda n: n.visits, reverse=True)

    return best_move_node.move, attacker_responses[:5]


# --- Public Interface Function ---

def get_best_defensive_action(initial_state, iterations=2000):
    """
    The main public function that sentinel.py will call.
    """
    print(f"\n[MCTS] Analyzing optimal defensive action for {initial_state.get('type')}...")
    start_time = time.time()
    
    # Run the MCTS algorithm
    best_defensive_move, likely_attacker_responses = run_mcts(initial_state, iterations=iterations)
    
    end_time = time.time()
    print(f"[MCTS] Analysis complete in {end_time - start_time:.2f} seconds.")

    # 1. Display the "5 next most likely moves" (attacker's *responses*)
    print("\n--- [MCTS] Top 5 Predicted Attacker Responses (if we take this action) ---")
    if likely_attacker_responses:
        for i, node in enumerate(likely_attacker_responses):
            print(f"  {i+1}. {node.move} (Analyzed {node.visits} times)")
    else:
        print("  (No subsequent attacker moves simulated for this branch)")

    # 2. Select and display the block
    print("\n--- [MCTS] Recommended Defensive Action ---")
    print(f"Action: {best_defensive_move}")
    
    # This function just returns the recommendation. 
    # sentinel.py will be responsible for *executing* it.
    return best_defensive_move, [node.move for node in likely_attacker_responses]
