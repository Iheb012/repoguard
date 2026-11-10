// Ordinary server: reads named settings and makes an ordinary request.
const { HOST } = process.env;
const port = process.env.PORT || 3000;

async function load() {
  const res = await fetch("https://api.example.test/data");
  return res.json();
}

console.log(HOST, port, load);
