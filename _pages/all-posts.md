---
permalink: /posts/
title: "All Posts"
excerpt: "All posts so far"
author_profile: true
toc: false
---

{% include base_path %}
{% for post in site.posts %}
  {% capture year %}{{ post.date | date: '%Y' }}{% endcapture %}
  {% if year != written_year %}
    {% capture written_year %}{{ year }}{% endcapture %}
  {% endif %}
  {% include archive-single.html %}
{% endfor %}
