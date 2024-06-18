/*
 * Copyright ${year} Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.redhat.ecosystemappeng.onguard.osvingester.cli;

import com.redhat.ecosystemappeng.onguard.osvingester.service.EcosystemLoader;

import picocli.CommandLine;

@CommandLine.Command(name = "gcs", description = "Loads Vulnerability data from OSV Google Cloud Storage Bucket")
public class GCSIngesterCommand implements Runnable {
  @CommandLine.Option(names = { "--ecosystem" }, description = "Ecosystem to load", defaultValue = "all")
  String ecosystem;

  private final EcosystemLoader loader;

  public GCSIngesterCommand(EcosystemLoader loader) {
    this.loader = loader;
  }

  @Override
  public void run() {
    if ("all".equalsIgnoreCase(ecosystem)) {
      loader.loadAll().collect().asList().await().indefinitely();
    } else {
      loader.load(ecosystem).await().indefinitely();
    }
  }
}
