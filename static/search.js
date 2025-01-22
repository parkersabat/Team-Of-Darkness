document.getElementById("searchInput").addEventListener("input", async (event) => {
    const query = event.target.value.trim();

    if (query.length >= 3) { // Trigger search after 3 characters
        try {
            const response = await fetch(`/search?q=${encodeURIComponent(query)}`);
            if (response.ok) {
                const results = await response.json();
                displayResults(results);
            } else {
                const errorData = await response.json();
                document.querySelector(".Urls").innerHTML = `<p>${errorData.error}</p>`;
            }
        } catch (error) {
            document.querySelector(".Urls").innerHTML = `<p>Something went wrong. Please try again later.</p>`;
        }
    } else {
        // Optionally clear results when query is too short
        document.querySelector(".Urls").innerHTML = "";
    }
});
