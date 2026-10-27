const button = document.getElementById("analyse-btn"); //Connects analyse button to script
 
button.addEventListener("click", async function() {

    //collection of all inputed data from webstie
    const posted_sender = document.getElementById("sender").value;
    const posted_subject = document.getElementById("subject").value;
    const posted_body = document.getElementById("body").value;
    const extraUrl = document.getElementById("extraUrl").value.trim();
  
    const errorMessage = document.getElementById("error-message");// Connects error message to script
    if (
        posted_sender.trim() === "" ||
        posted_subject.trim() === "" ||
        posted_body.trim() === "") {

         errorMessage.textContent = "Please fill in all fields."; // Shows the error
        return; // Stops the analysis
    }

    errorMessage.textContent = ""; // Clears the error when the inputs are valid


    button.textContent = "Analysing..."; // Changes the button text
    button.disabled = true; // Stops the user clicking it again

    // Stop analysis if the sender email is invalid
    if (!sender.checkValidity()) {
        errorMessage.textContent = "Please enter a valid sender email.";
        return;
    }
   // fetch sends data inside its brakcets to api, await tells js to wait for the response before continuing, 
    const response = await fetch("http://127.0.0.1:8000/analyse", {
        method: "POST", //POST method is used to send data to the API
        headers: {
            "Content-Type": "application/json" //Content-Type header is set to application/json to indicate that the request body contains JSON data
        },
        body: JSON.stringify({ //sstringfy converts the data into a JSON string to match required data type for the API
            sender: posted_sender,
            body: posted_body,  
            subject: posted_subject,
            hiddenURL: extraUrl
        })
    });

    const result = await response.json(); //repsonse.json() is used to extract th json data from the resposne object containing all the results and stores it in results

    button.textContent = "Analyse Email"; // Changes the text back
    button.disabled = false; // Allows the button to be clicked again

    document.querySelector(".results").style.display = "block"; // Shows the results after analysis

    console.log(result); // saves results to console for future use
    let output = "";// creates an empty string to store the url reasons, EMPTY BY DEFAULT TO AVOID ERRORS WHEN NO URLS ARE FOUND

    for (const urlData of result.url_reasons) { //go throguh all url dictionaries in the url_reasons list and store them in urlData
    const entries = Object.entries(urlData);// converts the urlData dictionary into an array of key-value pairs and stores it in entries
    for (const [url, warnings] of entries) { //go through all key-value pairs in the entries array and store the key in url and the value in warnings
        output += url + "\n";
        output += warnings.join("\n") + "\n\n"; 
    }
}

   if (result.url_reasons.length === 0) {
    document.getElementById("url_reasons").textContent = "No URLs found.";
    } else {
        document.getElementById("url_reasons").textContent = output;
    }

    
    const riskElement = document.getElementById("risk_level");

    riskElement.textContent = result.risk; // Shows the risk level
    riskElement.className = ""; // Removes the previous colour
    if (result.risk === "Low Risk") {
        riskElement.classList.add("low-risk");
    }
    else if (result.risk === "Moderate Risk") {
        riskElement.classList.add("moderate-risk");
    }
    else {
        riskElement.classList.add("high-risk");
    }   //displays the risk results on the webpage when found   

   if (result.email_reasons.length === 0) {
    document.getElementById("email_reasons").textContent = "No suspicious email content found.";
    } else {
        document.getElementById("email_reasons").textContent = result.email_reasons.join("\n");
    }


    document.getElementById("risk_score").textContent = result.risk_score; //displays the risk score on the webpage when found
});


const clearButton = document.getElementById("clear-btn"); // Gets the Clear button

clearButton.addEventListener("click", function() {

    document.getElementById("error-message").textContent = ""; // Removes the old error 
    document.getElementById("sender").value = ""; // Clears the sender
    document.getElementById("subject").value = ""; // Clears the subject
    document.getElementById("body").value = ""; // Clears the email content
    document.getElementById("extraUrl").value = ""; // Clears the extra url content

    document.querySelector(".results").style.display = "none"; // Hides the old results

});