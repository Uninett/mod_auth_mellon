<?xml version="1.0" encoding="UTF-8"?>
<!--
     Convert urn:mace:shibboleth:2.0:attribute-map to MellonSetEnv statements

     Author: Pat Riehecky <riehecky@fnal.gov>
     Copyright (2019).  Fermi Research Alliance, LLC
-->
<xsl:stylesheet version="1.0"
     xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
     xmlns:map="urn:mace:shibboleth:2.0:attribute-map"
>
  <xsl:output method="text" omit-xml-declaration="yes" indent="no"/>

  <xsl:template match="/map:Attributes">
    <xsl:apply-templates select="map:Attribute">
      <xsl:sort select="@id" data-type="text" />
      <xsl:sort select="@name" data-type="text" order="descending"/>
    </xsl:apply-templates>
  </xsl:template>

  <xsl:template match='map:Attribute'>
    <xsl:value-of select="concat('MellonSetEnvNoPrefix ', @id, ' ' , @name)"/><xsl:text>&#xa;</xsl:text>
  </xsl:template>

</xsl:stylesheet>
