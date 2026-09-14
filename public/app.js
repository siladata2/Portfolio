async function loadProjects() {

  const grid =
    document.getElementById(
      "projectsGrid"
    );

  const count =
    document.getElementById(
      "projectCount"
    );


  try {

    const response =
      await fetch(
        "/api/projects"
      );


    if (!response.ok) {

      throw new Error(
        "Failed to load"
      );

    }


    const projects =
      await response.json();


    count.textContent =
      `${projects.length} ${
        projects.length === 1
          ? "Project"
          : "Projects"
      }`;


    if (!projects.length) {

      grid.innerHTML = `
        <div class="loading">
          No projects available yet.
        </div>
      `;

      return;

    }


    grid.innerHTML =
      projects
        .map(
          project => `

          <article class="project-card">

            <div class="project-image">

              ${
                project.image

                ?

                `
                <img
                  src="${escapeHTML(
                    project.image
                  )}"
                  alt="${escapeHTML(
                    project.name
                  )}"
                >
                `

                :

                `
                <div class="image-placeholder">
                  ${escapeHTML(
                    project.name
                      .charAt(0)
                      .toUpperCase()
                  )}
                </div>
                `

              }

            </div>


            <div class="project-content">

              <h3>
                ${escapeHTML(
                  project.name
                )}
              </h3>


              <p>

                ${escapeHTML(
                  project.description ||
                  "SILA TECH Project"
                )}

              </p>


              <div class="project-actions">

                <a
                  href="${escapeHTML(
                    project.path
                  )}"
                  class="open-btn"
                >
                  Open Project
                </a>


                ${
                  project.postUrl

                  ?

                  `
                  <a
                    href="${escapeHTML(
                      project.postUrl
                    )}"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="post-btn"
                  >
                    Post
                  </a>
                  `

                  :

                  ""

                }

              </div>

            </div>

          </article>

        `
        )
        .join("");


  } catch (error) {

    console.error(error);

    grid.innerHTML = `
      <div class="loading">
        Failed to load projects.
      </div>
    `;

  }

}



function escapeHTML(value) {

  return String(
    value ?? ""
  ).replace(
    /[&<>"']/g,
    function (char) {

      return {

        "&": "&amp;",

        "<": "&lt;",

        ">": "&gt;",

        '"': "&quot;",

        "'": "&#039;"

      }[char];

    }
  );

}



document.getElementById(
  "year"
).textContent =
  new Date().getFullYear();


loadProjects();